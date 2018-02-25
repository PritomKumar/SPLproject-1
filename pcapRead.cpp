#include<iostream>
#include<sstream>
#include<stdio.h>
#include <fstream>

using namespace std;

typedef struct pcapGlobalHeader {

        char magicNumber[4];   		// magic number , 4 byte
        char majorVersionNumber[2];  // major version number ,2 byte
        char minorVersionNumber[2];  // minor version number , 2 byte
        char timeOffsetGMT[4];       // GMT to local correction , 4 byte
        char sigfigs[4];        		// accuracy of timestamps , 4 byte
        char maxSnapshotLenght[4];    // max length of captured packets, in octets , 4 byte
        char linkLayerProtocol[4];    // data link type , 4 byte
};

int main(){

	string s;

	FILE *fp;
	unsigned char ch;
	unsigned char str[16];

	fp = fopen("samplePcap.pcap","rb");

	pcapGlobalHeader globhdr;

	fread(&globhdr, sizeof(struct pcapGlobalHeader), 1, fp);

	for(int i =0 ; i<4 ; i++){
		cout << globhdr.magicNumber[i] << " " ; //hahahahhahaha I am a genius;
	}

	int i=0;
/*
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

*/


}
