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
#include <iostream>

#include "config.hpp"
#include "lib.hpp"

using namespace std;

void outputHelp()
{
	cout << "Usage: sign <keyfilename> <filename>" << endl;
	cout << "\tThis tool will load the private key from <keyfilename>, read the data in <filename> and sign it, creating <filename>.sig" << endl;
}

int main(int argc, char const **argv)
{
	string input_filename;
	string output_filename;
	string key_filename;

	--argc; ++argv;
	if (argc != 2)
	{
		outputHelp();
		return 1;
	}
	key_filename = *argv;
	--argc; ++argv;
	input_filename = *argv;
	output_filename = input_filename + ".sig";

	auto key(loadPrivateKey(key_filename));
	auto digest(digestFile(input_filename));
	auto signature(sign(key.get(), digest));
	auto output_file(openFile(output_filename));
	BIO_write(output_file.get(), &signature[0], static_cast< int >(signature.size()));

	return 0;
}
