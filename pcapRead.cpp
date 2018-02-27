#include<iostream>
#include<sstream>
#include<stdio.h>
#include <fstream>

using namespace std;

typedef struct pcapGlobalHeader { 	//total 24 bytes

        unsigned char magicNumber[4];   		// magic number , 4 byte
        unsigned char majorVersionNumber[2];   // major version number ,2 byte
        unsigned char minorVersionNumber[2];   // minor version number , 2 byte
        unsigned char timeOffsetGMT[4];        // GMT to local correction , 4 byte
        unsigned char sigfigs[4];        	   // accuracy of timestamps , 4 byte
        unsigned char maxSnapshotLenght[4];    // max length of captured packets, in octets , 4 byte
        unsigned char linkLayerProtocol[4];    // data link type , 4 byte
};

typedef struct packetHeader{
		unsigned char timeStamps[4];				// timestamps in seconds from 1970
		unsigned char packetCaptureTime[4];		// capture time in microseconds
		unsigned char packetSizeFromData[4];		// saved data size in packets
		unsigned char packetLengthFromWire[4];	// packet length captured from wire

};

int main(){

	string s;

	FILE *fp;
	unsigned char ch;
	unsigned char str[16];

	fp = fopen("sample.pcap","rb");

	pcapGlobalHeader globhdr;
	packetHeader  pachdr;

	fread(&globhdr, sizeof(struct pcapGlobalHeader), 1, fp);
	fread(&pachdr , sizeof(struct packetHeader) , 1 , fp);

    unsigned char cc;
    int x;
    cc = pachdr.packetSizeFromData[3];
    x= (int) cc;
    //x = x | cc;
    x = x<< 8 ;
    cc = pachdr.packetSizeFromData[2];
    x = x | cc;
    x = x<< 8 ;
    cc = pachdr.packetSizeFromData[1];
    x = x | cc;
    x = x<< 8 ;
    cc = pachdr.packetSizeFromData[0];
    x = x | cc;

    cout << x <<endl;



	for(int i =0 ; i<4 ; i++){

		//cout << (int)globhdr.magicNumber[i] << " " ; //hahahahhahaha I am a genius;
		//cout << (char)globhdr.magicNumber[i] << " " ; //hahahahhahaha I am a genius;
		//printf("%.02x " , globhdr.magicNumber[i]&(0xff));
	}

	for(int i =0 ; i<4 ; i++){
		unsigned int l = (int)pachdr.timeStamps[i];
		//cout << l << " " ; //hahahahhahaha I am a genius;
		//cout << (char)pachdr.timeStamps[i] << " " ; //hahahahhahaha I am a genius;
		//printf("%.02x " , pachdr.timeStamps[i]&(0xff));
	}
// just need to convert the numbers in appropriate hex value and convert them to integer
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
