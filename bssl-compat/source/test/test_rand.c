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

#include "bssl_compat/openssl/rand.h"

#include <stdio.h>
#include <stdint.h>

int main (void) {
	int r, i;
	uint8_t a[16] = { 0 };
	uint8_t b[16] = { 0 };

	r = RAND_bytes(a, sizeof(a));
	printf("RAND_bytes returned %d: ", r);

	for (i = 0; i < sizeof(a); i++)
		printf("%02x ", a[i]);
	printf("\n");

	r = RAND_bytes(b, sizeof(b));
	printf("RAND_bytes returned %d: ", r);

	for (i = 0; i < sizeof(b); i++)
		printf("%02x ", b[i]);
	printf("\n");

	for (i = 0; i < sizeof(a); i++) {
		if (a[i] != b[i])
			return 0;
	}

	return 1;
}
