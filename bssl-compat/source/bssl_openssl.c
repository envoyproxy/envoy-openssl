/*
 * Copyright (C) 2022 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>

#include "bssl_compat/bssl_openssl.h"

#define OPENSSL_LIBCRYPTO "libcrypto.so"
#define OPENSSL_LIBSSL    "libssl.so"

/* Constructor/destructor functions to run when library is loaded/unloaded */
static void bssl_openssl_init(void)  __attribute__ ((constructor));
static void bssl_openssl_close(void) __attribute__ ((destructor));

static void *libcrypto;
static void *libssl;
struct openssl_func openssl;

/* Load needed OpenSSL symbols, fail hard if the attempt is unsuccessful  */
static void bssl_openssl_init(void) {

	libcrypto = dlopen(OPENSSL_LIBCRYPTO, RTLD_NOW | RTLD_LOCAL);
	if (libcrypto == NULL)
		goto err;

	libssl = dlopen(OPENSSL_LIBSSL, RTLD_NOW | RTLD_LOCAL);
	if (libcrypto == NULL)
		goto err;

	if (!(openssl.RAND_bytes =
	      (int(*)(unsigned char *, int))(dlsym(libcrypto, "RAND_bytes"))))
		goto err;

	if(!(openssl.SSL_ctrl =
	     (long(*)(SSL *ssl, int cmd, long larg, void *parg))dlsym(libssl, "SSL_ctrl")))
		goto err;

	if(!(openssl.SSL_do_handshake =
	     (int(*)(SSL *))dlsym(libssl, "SSL_do_handshake")))
		goto err;

	if(!(openssl.SSL_get_error =
	     (int(*)(const SSL*, int))dlsym(libssl, "SSL_get_error")))
		goto err;

	if(!(openssl.SSL_get_all_async_fds =
	     (int(*)(SSL *, OSSL_ASYNC_FD *, size_t *))dlsym(libssl, "SSL_get_all_async_fds")))
		goto err;

	return;

 err:
	fprintf(stderr, "%s: %s\n", __FUNCTION__, dlerror());
	exit(ELIBACC);
}

static void bssl_openssl_close(void) {
	dlclose(libcrypto);
	dlclose(libssl);
}
