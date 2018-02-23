#include<iostream>
#include<sstream>
#include<stdio.h>
#include <fstream>

using namespace std;


int main(){

	string s;

	FILE *fp;
	unsigned char ch;
	unsigned char str[16];

	fp = fopen("samplePcap.pcap","rb");

	int i=0;

	while(!feof(fp)){

		fread(&ch,1,1,fp);

		str[i] = ch;
		i++;

		printf("%.02x " , ch&(0xff));

		if(i%8==0) cout << "   " ;

		if(i%16==0){
            for(int j=0;j<16;j++){
                if(isprint(str[j]))  //sees if character is printable
                    cout << str[j] ;
                else
                    cout << ".";
            }

            printf(" \n");
            i=0;
        }


	}




}
