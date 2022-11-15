#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/Tooling.h"
#include "clang/Tooling/Execution.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Signals.h"
#include "llvm/ADT/Statistic.h"
#include <iostream>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <cstdlib>
#include <regex>
#include <glob.h>



namespace opt {
  static std::filesystem::path    srcpath   ("/usr/include");
  static std::vector<std::string> srcincl = { "openssl/*.h" };
  static std::vector<std::string> srcskip = { "openssl/asn1_mac.h", "openssl/opensslconf-x86_64.h" };
  static std::filesystem::path    output  = std::filesystem::current_path();
  static std::string              prefix  = "xxx";
  static bool                     force   = false;

  static std::vector<std::string> headers; // Relative to srcpath e.g. "openssl/x509.h"
};



class MyFrontendAction: public clang::ASTFrontendAction {

  public:

    std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(clang::CompilerInstance &compiler, llvm::StringRef InFile) override;

    bool BeginSourceFileAction(clang::CompilerInstance &compiler) override;
    void EndSourceFileAction() override;

    bool prefixable(const std::string &path) {
      if(std::find(opt::headers.begin(), opt::headers.end(), std::filesystem::proximate(path, opt::output / opt::prefix)) != opt::headers.end()) {
        return true;
      }
      return false;
    }

    bool prefixable(clang::SourceLocation sloc) {
      const clang::SourceManager &srcmgr = getCompilerInstance().getSourceManager();
      if(const clang::FileEntry *declfile = srcmgr.getFileEntryForID(srcmgr.getFileID(sloc))) {
        return prefixable (declfile->getName().str());
      }
      return false;
    }

    void prefix(clang::StringRef identifier, bool linkable = false) {
      m_identifiers.insert(identifier.str());
      if (linkable) {
        m_linkable.insert(identifier.str());
      }
    }

  private:

    std::set<std::string> m_identifiers; // To be prefixed
    std::set<std::string> m_linkable; // Subset of m_identifiers
};


class MyASTConsumer: public clang::ASTConsumer, public clang::RecursiveASTVisitor<MyASTConsumer> {
  public:
    explicit MyASTConsumer(MyFrontendAction &frontend) :
        m_frontend(frontend) {
    }

    void HandleTranslationUnit(clang::ASTContext &context) {
      TraverseDecl(context.getTranslationUnitDecl());
    }

    bool VisitFunctionDecl(clang::FunctionDecl *node) {
      if ((node->getName().size() > 0) && m_frontend.prefixable(node->getLocation())) {
        m_frontend.prefix(node->getName(), true);
      }
      return true;
    }

    bool VisitRecordDecl(clang::RecordDecl *node) {
      if ((node->getName().size() > 0) && m_frontend.prefixable(node->getLocation())) {
        m_frontend.prefix(node->getName());
      }
      return true;
    }

    bool VisitTypedefDecl(clang::TypedefDecl *node) {
      if (m_frontend.prefixable(node->getLocation())) {
        m_frontend.prefix(node->getName());
      }
      return true;
    }

  private:

    MyFrontendAction &m_frontend;
};


class MyPPCallbacks: public clang::PPCallbacks {
  public:

    explicit MyPPCallbacks(MyFrontendAction &frontend, clang::Preprocessor &preprocessor) :
        m_frontend(frontend),
        m_preprocessor(preprocessor) {
    }

    void MacroDefined(const clang::Token &token, const clang::MacroDirective *directive) override {
      if (m_frontend.prefixable(token.getLocation())) {
        m_frontend.prefix(m_preprocessor.getSpelling(token));
      }
    }

    void MacroUndefined(const clang::Token &token, const clang::MacroDefinition &definition, const clang::MacroDirective *undef) override {
      if (m_frontend.prefixable(token.getLocation())) {
        m_frontend.prefix(m_preprocessor.getSpelling(token));
      }
    }

  private:

    MyFrontendAction &m_frontend;
    clang::Preprocessor &m_preprocessor;
};


class CompilationDatabase : public clang::tooling::CompilationDatabase
{
  public:

    std::vector<clang::tooling::CompileCommand> getCompileCommands(llvm::StringRef file) const override {
      std::vector<std::string> cmdline = {
          "dummy",
          std::string("-I") + opt::output.string(),
          "-I/usr/lib64/clang/" LLVM_VERSION_STRING "/include/",
          file.str()
      };
      return { clang::tooling::CompileCommand(".", file, cmdline, "") };
    }
};



std::unique_ptr<clang::ASTConsumer> MyFrontendAction::CreateASTConsumer(clang::CompilerInstance &compiler, llvm::StringRef InFile) {
  return std::make_unique<MyASTConsumer>(*this);
}

bool MyFrontendAction::BeginSourceFileAction(clang::CompilerInstance &compiler) {
  auto &preprocessor = compiler.getPreprocessor();
  std::unique_ptr<MyPPCallbacks> ppcallbacks(new MyPPCallbacks(*this, preprocessor));
  preprocessor.addPPCallbacks(std::move(ppcallbacks));
  return true;
}

void MyFrontendAction::EndSourceFileAction() {
  std::regex regex("[a-zA-Z_][a-zA-Z0-9_]*");

  for (const auto &header : opt::headers) {
    auto path = opt::output / opt::prefix / header;
    std::string buffer;

    // Read the source header
    {
      std::ifstream ifstr(path);
      std::stringstream isstr;
      isstr << ifstr.rdbuf();
      buffer = isstr.str();
    }

    // Write the destination header with prefixes inserted
    {
      std::ofstream ofstr(path);
      std::smatch match;
      std::string::const_iterator searchStart(buffer.cbegin());
      std::string suffix;

      while (std::regex_search(searchStart, buffer.cend(), match, regex)) {
        std::string matchstr = match[0];
        if (m_identifiers.find(matchstr) != m_identifiers.end()) {
          ofstr << match.prefix() << opt::prefix << '_' << matchstr;
        }
        else if(matchstr.find("OPENSSL_") == 0) {
          ofstr << match.prefix() << opt::prefix << '_' << matchstr;
        }
        else {
          ofstr << match.prefix() << matchstr;
        }
        searchStart = match.suffix().first;
        suffix = match.suffix();
      }
      ofstr << suffix;
    }
  }

  // Write linker script
  {
    std::ofstream ofstr ((opt::output / opt::prefix).string() + ".ld");
    for (auto symbol : m_linkable) {
      ofstr << "PROVIDE(" << opt::prefix << "_" << symbol << " = " << symbol << ");" << std::endl;
    }
  }
}




static bool usage(int exitcode) {
  std::cerr << "USAGE: prefixer [options]" << std::endl;
  std::cerr << std::endl;
  std::cerr << "OPTIONS:" << std::endl;
  std::cerr << std::endl;
  std::cerr << "  --src-path <path>       Directory containing the openssl headers e.g. /usr/include" << std::endl;
  std::cerr << "  --src-incl <pattern>    Header files to be prefixed e.g. openssl/*.h" << std::endl;
  std::cerr << "  --src-skip <pattern>    Header files to be skipped e.g. openssl/asn1_mac.h" << std::endl;
  std::cerr << "  --prefix <string>       The prefix to be applied to functions, types & macros" << std::endl;
  std::cerr << "  --output <path>         Output directory for prefixed headers and linker script" << std::endl;
  std::cerr << "  --force                 Delete & replace the output directory if it already exists" << std::endl;
  std::cerr << std::endl;

  if (exitcode) {
    exit(exitcode);
  }

  return true;
}

int main(int argc, const char **argv) {

  llvm::sys::PrintStackTraceOnErrorSignal(argv[0]);

  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if ((arg == "--src-path") && ((++i < argc) || usage(-1))) {
      opt::srcpath = std::filesystem::canonical(argv[i]);
    }
    else if ((arg == "--src-incl") && ((++i < argc) || usage(-1))) {
      opt::srcincl.push_back(argv[i]);
    }
    else if ((arg == "--src-skip") && ((++i < argc) || usage(-1))) {
      opt::srcskip.push_back(argv[i]);
    }
    else if ((arg == "--prefix") && ((++i < argc) || usage(-1))) {
      opt::prefix = argv[i];
    }
    else if ((arg == "--output") && ((++i < argc) || usage(-1))) {
      opt::output = argv[i];
    }
    else if (arg == "--force") {
      opt::force = true;
    }
    else if (arg == "--help") {
      usage(0);
      exit(0);
    }
    else {
      llvm::errs() << "Unrecognised option : " << arg << "\n";
      exit(-1);
    }
  }

  // Ensure the output directory doesn't already exist
  if (std::filesystem::exists(opt::output / opt::prefix)) {
    if (opt::force == true) {
      std::filesystem::remove_all(opt::output / opt::prefix);
    } else {
      llvm::errs() << "Output directory " << opt::output / opt::prefix << " already exists\n";
      return -1;
    }
  }

  // Build the list of header files to be processed
  if (!std::filesystem::is_directory(opt::srcpath)) {
    llvm::errs() << "Source directory " << opt::srcpath << " does not exist\n";
    return -1;
  }
  else {
    glob_t globbuf;
    int globflags = GLOB_MARK;

    for (auto i : opt::srcincl) {
      auto pattern = opt::srcpath / i;
      glob(pattern.c_str(), globflags, 0, &globbuf);
      globflags |= GLOB_APPEND;
    }

    for (auto i = 0; i < globbuf.gl_pathc; i++) {
      opt::headers.push_back(std::filesystem::proximate(globbuf.gl_pathv[i], opt::srcpath));
    }

    globfree (&globbuf);
  }

  std::filesystem::create_directories (opt::output / opt::prefix);
  std::filesystem::path srcfile = (opt::output / opt::prefix).string() + ".c";
  {
    std::ostringstream subts;
    std::ostringstream files;
    std::ofstream str (srcfile);
    for (std::string hdr : opt::headers) {
      auto srchdr = opt::srcpath / hdr;
      auto dsthdr = opt::output / opt::prefix / hdr;

      std::filesystem::create_directories(dsthdr.parent_path());
      std::filesystem::copy_file(srchdr, dsthdr);

      subts << " -e 's!<" << hdr << ">!\"" << opt::prefix << "/" << hdr << "\"!g'";
      files << " " << opt::output / opt::prefix << "/" << hdr;

      if (std::find (opt::srcskip.begin(), opt::srcskip.end(), hdr) == opt::srcskip.end()) {
        str << "#include \"" << opt::prefix << "/" << hdr << "\"" << std::endl;
      }
    }
    std::system((std::string("sed -i ") + subts.str() + files.str()).c_str());
  }

  clang::tooling::ClangTool tool(CompilationDatabase(), { srcfile });
  int ret = tool.run(clang::tooling::newFrontendActionFactory<MyFrontendAction>().get());

  std::filesystem::remove(srcfile);

  return ret;
}

