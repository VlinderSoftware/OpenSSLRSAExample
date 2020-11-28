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
#include "lib.hpp"

#include <stdexcept>
#include <vector>

#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "config.hpp"

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4996)
#include <openssl/applink.c>
#pragma warning(pop)
#endif

using namespace std;

namespace {
	int passkeyCallback__(char* buf, int size, int rwflag, void* u)
	{
		vector< unsigned char >* key(static_cast<vector< unsigned char >*>(u));
		if ((unsigned int)size < key->size())
		{
			throw runtime_error("key too large");
		}
		else
		{ /* we have enough space */
		}
		copy(key->begin(), key->end(), buf);
		return static_cast< int >(key->size());
	}

	int bignumGenerationCallback__(int, int, BN_GENCB*)
	{
		return 1;
	}
}


unique_ptr< EVP_PKEY, function< void(EVP_PKEY*) > > generateRSAPrivateKey(unsigned int bits)
{
	auto rsa_deleter([](RSA* rsa) { RSA_free(rsa); });
	unique_ptr< RSA, decltype(rsa_deleter) > rsa(RSA_new(), rsa_deleter);
	if (!rsa) throw bad_alloc();
	auto bn_deleter([](BIGNUM* bn) { BN_free(bn); });
	unique_ptr< BIGNUM, decltype(bn_deleter) > exponent(BN_new(), bn_deleter);
	if (!exponent) throw bad_alloc();
	BN_set_word(exponent.get(), RSA_F4);
	auto bn_gencb_deleter([](BN_GENCB* cb) { BN_GENCB_free(cb); });
	unique_ptr< BN_GENCB, decltype(bn_gencb_deleter) > cb(BN_GENCB_new(), bn_gencb_deleter);
	if (!cb) throw bad_alloc();

	BN_GENCB_set(cb.get(), bignumGenerationCallback__, nullptr);

	unsigned int const primes(
		bits < 1024 ? 2
		: bits < 4096 ? 3
		: bits < 8192 ? 4
		: 5
	);

	if (1 != RSA_generate_multi_prime_key(rsa.get(), bits, primes, exponent.get(), cb.get())) throw runtime_error("Something more eloquent here");

	auto evp_pkey_deleter([](EVP_PKEY* k) { EVP_PKEY_free(k); });
	unique_ptr< EVP_PKEY, decltype(evp_pkey_deleter) > pkey(EVP_PKEY_new(), evp_pkey_deleter);
	if (!pkey) throw bad_alloc();
	if (!EVP_PKEY_assign_RSA(pkey.get(), rsa.get()))
	{
		throw runtime_error("Failed to assign key to pkey");
	}
	else
	{ /* all is well */
	}
	rsa.release();

	return pkey;
}

unique_ptr< BIO, function< void(BIO*) > > openFile(string const& filename, bool for_reading/* = false*/)
{
	auto bio_deleter([](BIO* bio) { BIO_free_all(bio); });
	if (filename == "-") // stdout, depending on read_only bit
	{
		return unique_ptr< BIO, decltype(bio_deleter) >(BIO_new_fp(for_reading ? stdin : stdout, BIO_NOCLOSE), bio_deleter);
	}
	else
	{
		return unique_ptr< BIO, decltype(bio_deleter) >(BIO_new_file(filename.c_str(), for_reading ? "rb" : "wb"), bio_deleter);
	}
}

void writePrivateKey(string const& filename, EVP_PKEY* key)
{
	auto bio(openFile(filename));
	string password(PRIVATE_KEY_PASSWORD);
	vector< unsigned char > passkey(password.begin(), password.end());
	if (!PEM_write_bio_PrivateKey(bio.get(), key, EVP_aes_256_cbc(), &passkey[0], static_cast<int>(passkey.size()), nullptr, nullptr))
	{
		throw runtime_error("Failed to write private key to file");
	}
	else
	{ /* all is well */ }
}

void writePublicKey(string const& filename, EVP_PKEY* key)
{
	auto bio(openFile(filename));
	if (!PEM_write_bio_PUBKEY(bio.get(), key))
	{
		throw runtime_error("Failed to write public key to file");
	}
	else
	{ /* all is well */ }
}

unique_ptr< EVP_PKEY, function< void(EVP_PKEY*) > > loadPrivateKey(string const& filename)
{
	auto bio(openFile(filename, true));
	string password(PRIVATE_KEY_PASSWORD);
	vector< unsigned char > passkey(password.begin(), password.end());

	auto evp_pkey_deleter([](EVP_PKEY* k) { EVP_PKEY_free(k); });
	unique_ptr< EVP_PKEY, decltype(evp_pkey_deleter) > pkey(PEM_read_bio_PrivateKey(bio.get(), nullptr, passkeyCallback__, &passkey), evp_pkey_deleter);
	if (!pkey) throw bad_alloc();

	return pkey;
}

unique_ptr< EVP_PKEY, function< void(EVP_PKEY*) > > loadPublicKey(string const& filename)
{
	auto bio(openFile(filename, true));

	auto evp_pkey_deleter([](EVP_PKEY* k) { EVP_PKEY_free(k); });
	unique_ptr< EVP_PKEY, decltype(evp_pkey_deleter) > pkey(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, 0), evp_pkey_deleter);
	if (!pkey) throw bad_alloc();

	return pkey;
}

vector< unsigned char > digestFile(string const& filename)
{
	auto bio_deleter([](BIO* bio) { BIO_free_all(bio); });

	unique_ptr< BIO, decltype(bio_deleter) > md_bio(BIO_new(BIO_f_md()), bio_deleter);
	BIO *md_bio_raw(md_bio.get());
	BIO_set_md(md_bio.get(), EVP_get_digestbynid(NID_sha256));

	auto file_bio(openFile(filename, true));
	BIO *bio = BIO_push(md_bio.get(), file_bio.get());
	md_bio.release();

	// read the file through the chain
	int rdlen(0);
	char buf[1024];
	do {
		rdlen = BIO_read(bio, buf, sizeof(buf));
	} while (rdlen > 0);

	char mdbuf[EVP_MAX_MD_SIZE];
	int mdlen(BIO_gets(md_bio_raw, mdbuf, EVP_MAX_MD_SIZE));

	return vector< unsigned char >(mdbuf, mdbuf + mdlen);
}

vector< unsigned char > sign(EVP_PKEY* key, vector< unsigned char > const& digest)
{
	RSA *rsa(EVP_PKEY_get0_RSA(key));
	vector< unsigned char > retval(RSA_size(rsa));
	unsigned int retval_size(static_cast< unsigned int >(retval.size()));
	if (!RSA_sign(NID_sha256, &digest[0], static_cast< unsigned int >(digest.size()), &retval[0], &retval_size, rsa))
	{
		throw runtime_error("Failed to generate RSA signature");
	}
	else
	{ /* all is well */ }
	retval.resize(retval_size);

	return retval;
}

vector< unsigned char > loadFile(string const& filename)
{
	vector< unsigned char > retval;
	auto bio(openFile(filename, true));
	int rdlen(0);
	char buf[1024];
	do {
		rdlen = BIO_read(bio.get(), buf, sizeof(buf));
		if (rdlen > 0)
		{
			retval.insert(retval.end(), buf, buf + rdlen);
		}
		else
		{ /* didn't read anything */ }
	} while (rdlen > 0);

	return retval;
}

bool verify(EVP_PKEY* key, vector< unsigned char > const& signature, vector< unsigned char > const& digest)
{
	RSA* rsa(EVP_PKEY_get0_RSA(key));
	return RSA_verify(NID_sha256, &digest[0], static_cast< int >(digest.size()), &signature[0], static_cast< int >(signature.size()), rsa) == 1;
}
