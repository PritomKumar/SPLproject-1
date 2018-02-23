#include<iostream>
#include<sstream>
#include<stdio.h>
#include <fstream>

using namespace std;

typedef struct pcapGlobalHeader {

        unsigned long int magicNumber;   		// magic number , 4 byte
        unsigned short int majorVersionNumber;  // major version number ,2 byte
        unsigned short int minorVersionNumber;  // minor version number , 2 byte
        unsigned long int  timeOffsetGMT;       // GMT to local correction , 4 byte
        unsigned long int sigfigs;        		// accuracy of timestamps , 4 byte
        unsigned long int maxSnapshotLenght;    // max length of captured packets, in octets , 4 byte
        unsigned long int linkLayerProtocol;    // data link type , 4 byte
};

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

		int read ;

		if(i%8==0) cout << "   " ;

		if(i%16==0){
            for(int j=0;j<16;j++){

                if(isprint(str[j])) { //sees if character is printable
                    cout << str[j] ;
                }
                else {
                    cout << ".";
                }
            }

             cout << "   " ;
            for(int j=0;j<16;j++){
				read = str[j] ;
				cout << read  << " ";

            }

            printf(" \n");
            i=0;
        }


	}




}
