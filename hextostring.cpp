#include<iostream>
#include<sstream>
#include<stdio.h>

using namespace std;

int getHexVal(char c){
	  if(c >= '0' && c<= '9')
		return c - '0';
	  else if(c >= 'a' && c<= 'f')
		return c - 'a' + 10;
	  else if(c >= 'A' && c<= 'F')
		return c - 'A' + 10;
	  else
		return -1;//error
}
char* hexToAscii(char* hexStr)
{
	int hexLen = strlen(hexStr);

	char* asciiStr = new char(hexLen/2 + 1)

	for(int i = 0; i < nLen; i +=2)
	{
	  asciiStr[i/2] = (getHexVal(hexStr[i])*16 + getHexVal(hexStr[i+1]))
	}

	return asciiStr;
}

int main(){

	string s;

	File *fp;
	unsigned char ch;
	cin >> s;
	int t=0;

	for (int i = 0 ; i<s.length() ; i++ ){
		int t1,t2;
		ch = s[i];

		//printf("%.02x" , ch&(0xff));
		if(i%2==0) cout << " " ;
		/*
		int l1 = getHexVal(s[i]);
		int l2 = getHexVal(s[i+1]);
		t1 = l1*16;
		t2 = l2;
		t = t1 + t2;
		cout << (char)t << " " ;
		t=0;*/
	}



/*

*/
	/*
	string hex;

	cin >> hex;


    int sixteensDig = (hex[0] - 48) * 16;
    int onesDig = hex[1];
	int l;

    if ( (onesDig >= 'a') && (onesDig <= 'f') )
        onesDig == onesDig -32;

    if (onesDig < 65) {

         l = sixteensDig + onesDig - 48 ;
    } else {

        l =  sixteensDig + onesDig - 55 ;
    }
	//cout << (char)l << " " ;
*/
}
