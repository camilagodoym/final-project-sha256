#include "sha256.h"
//#include "book.txt"
#include<fstream>
#include<sstream>
#include<string>
#include <iostream>
using namespace std;

int main() {
	
/*booK = R"(...)*/

ifstream f("book.txt"); //taking file as inputstream
string booK;
if (f) {
	ostringstream ss;
	ss << f.rdbuf(); // reading data
	booK = ss.str(); // writting data to a new string
}

	string encrypting = SHA256::cifrar(booK);
	cout << "\nHash Result: " << encrypting;
	cout << "\n";
	
	return 0;
}
//source https://www.youtube.com/watch?v=lFjlTWOtnaI