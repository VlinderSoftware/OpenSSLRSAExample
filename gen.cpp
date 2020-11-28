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
#include <cassert>
#include <iostream>

#include "config.hpp"
#include "lib.hpp"

using namespace std;

void outputHelp()
{
	cout << "Usage: gen <basename>" << endl;
	cout << "\tThis tool will generate a 2048-bit RSA keypair and output it to two files:\n\t<basename>.pub for the public key and\n\t<basename>.key for the private key" << endl;
}

int main(int argc, char const **argv)
{
	string output_filename;
	--argc; ++argv; // skip the executable name

	if (!argc)
	{
		outputHelp();
		return 1;
	}
	else
	{ /* assume whatever's next is either an option or a filename */ }
	assert(argv);
	if ((*argv)[0] == '-')
	{
		switch ((*argv)[1])
		{
		case 0 :
			// output to stdout -- not an error
			break;
		case 'h' :
		default:
			outputHelp();
			return ((*argv)[1] == 'h') ? 0 : 1;
		}
	}
	else
	{
		output_filename = *argv;
		--argc; ++argv;
	}

	auto rsa_key(generateRSAPrivateKey(2048));
	writePublicKey(output_filename.empty() ? "-" : output_filename + ".pub", rsa_key.get());
	writePrivateKey(output_filename.empty() ? "-" : output_filename + ".key", rsa_key.get());

	return 0;
}
