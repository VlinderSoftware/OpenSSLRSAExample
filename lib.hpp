/* Copyright 2020  Ronald Landheer-Cieslak
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. */
#ifndef lib_hpp
#define lib_hpp

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <openssl/bio.h>
#include <openssl/evp.h>

std::unique_ptr< EVP_PKEY, std::function< void(EVP_PKEY*) > > generateRSAPrivateKey(unsigned int bits);
std::unique_ptr< BIO, std::function< void(BIO*) > > openFile(std::string const& filename, bool for_reading = false);
void writePrivateKey(std::string const& filename, EVP_PKEY* key);
void writePublicKey(std::string const& filename, EVP_PKEY* key);
std::unique_ptr< EVP_PKEY, std::function< void(EVP_PKEY*) > > loadPrivateKey(std::string const& filename);
std::unique_ptr< EVP_PKEY, std::function< void(EVP_PKEY*) > > loadPublicKey(std::string const& filename);
std::vector< unsigned char > digestFile(std::string const& filename);
std::vector< unsigned char > sign(EVP_PKEY *key, std::vector< unsigned char > const &digest);
std::vector< unsigned char > loadFile(std::string const& filename);
bool verify(EVP_PKEY* key, std::vector< unsigned char > const& signature, std::vector< unsigned char > const& digest);


#endif
