#include<iostream>
#include<string.h>
#include<stdio.h>
#include "packetCapture.cpp"
#include "headerFile.h"

using namespace std;

struct impCollection{

	unsigned long int sourceIPData ;
	unsigned long int destIPData ;
	unsigned long int sourcePortData ;
	unsigned long int destPortData ;
};

impCollection notable[100];

int totalPackets;
int totalInstances;

void readAndWriteFullPcapDataAsCharacterAndInteger(FILE *fp ){

    FILE *output;
	unsigned char ch;
	unsigned char str[16];
	int i=0;
	
	printf("Enter a file name to save All information on this PCAP file .\nFirst in hexadecimal , next in character and lastly in integer.\n");
	string s;
	string txtExtension= ".txt";
	cin >> s;
	s += txtExtension;
	cout << "The file name you have given is : " << s << endl ;
		
	char file[200];
	for(int j =0 ;  ; j++ ){

		file[j] = s[j];
		if(s[j] == '\0'){
			 file[j] = '\0';
			 break;
		}
	}

    output = fopen( file ,"w");
	cout << "All information on PCAP file . First in hexadecimal , next in character and lastly in integer." << endl<<endl;
	fprintf(output , "All Information in PCAP file is as follows ------ \n\n");
	fprintf(output , "\t\t\t\t\tHexadecimal  \t\t\t\t\t\t  Character    \t\t\t Integer \n\n");

	while(!feof(fp)){

		fread(&ch,1,1,fp);
		str[i] = ch;
		i++;
		printf("%.02X " , ch&(0xff));
		fprintf(output , "%.02X " , ch&(0xff));

		int read ;
		if(i%8==0) {
			cout << "   " ;
			fprintf(output , "   ");	
		}
		if(i%16==0){
            for(int j=0;j<16;j++){
                if(isprint(str[j])) {
					cout << str[j] ; //sees if character is printable
					fputc( str[j] ,output);
                }
                else {
					cout << ".";
					fputs(".", output);
				}

            }
			cout << "   " ;
			fprintf(output , "   ");
			fputs("   " , output);
            for(int j=0;j<16;j++){
				read = str[j] ;
				cout << read  << " ";
				fprintf(output , "%d " , read );
            }
            printf(" \n");
            fputs(" \n", output);
            i=0;
        }
	}
	
	
	cout << endl << endl;
	printf("Successfully created Text file that contains all data in Hexadecimal , Character and Integer. \n\n");
	fclose(output);
}

int dataSizeForIPHeader(unsigned char *ipLength){

	unsigned char cc;
    int x = 0;

	for(int i=0 ; i<2 ; i++){
		cc = ipLength[i];
		x = x<<8;
		x = x | cc;

	}
	return x;
}

int dataSize(packetHeader pachdr){
	unsigned char cc;
    int x = 0;

	for(int i=3 ; i>=0 ; i--){
		cc = pachdr.packetSizeFromData[i];
		x = x<<8;
		x = x | cc;

	}
	return x;
}

void initializeTestArray(int *sourceIPAdressDataArray ,int len){

    for(int i=0  ; i < len ; i++){
        sourceIPAdressDataArray[i] = -1;
    }
}

void printfDataArray(int counter){
	unsigned char ch;
	for (int i =0 ; i< counter ; i++){
		cout <<"\n\nPacket no : " << i+1 << " and Data Payload size : " <<  packet[i].dataPayloadSize <<endl <<endl;
		for(int j =0 ; j< packet[i].dataPayloadSize ; j++){
			ch = packet[i].data[j];
			printf("%.02x " , ch&(0xff));
		}
    }
}

unsigned long int IPHeaderSourceData(unsigned char *sourceIpAddr){

	unsigned char cc;
    unsigned long int x = 0;

	for(int i=0 ; i<3 ; i++){
		cc = sourceIpAddr[i];
		x = x<<8;
		x = x | cc;

	}
	return x;
}

unsigned long int IPHeaderDestinationData(unsigned char *destIpAddr){

	unsigned char cc;
    unsigned long int x = 0;

	for(int i=0 ; i<3 ; i++){
		cc = destIpAddr[i];
		x = x<<8;
		x = x | cc;

	}
	return x;
}

int sourcePortFromTcpHeader(unsigned char *sourcePort){

	unsigned char cc;
    int x = 0;

	for(int i=0 ; i<2 ; i++){
		cc = sourcePort[i];
		x = x<<8;
		x = x | cc;

	}
	return x;
}

int destPortFromTcpHeader(unsigned char *destPort){

	unsigned char cc;
    unsigned long int x = 0;

	for(int i=0 ; i<2 ; i++){
		cc = destPort[i];
		x = x<<8;
		x = x | cc;

	}
	return x;
}

unsigned long int sequenceNumber(unsigned char *sequenceNumber){

	unsigned char cc;
    int x = 0;

	for(int i=0 ; i<4 ; i++){
		cc = sequenceNumber[i];
		x = x<<8;
		x = x | cc;

	}
	return x;
}

void sortPacketsAccordingToSourceIPAddress(){

	for(int i=0 ; i< totalPackets -1; i++){
		for(int j=0 ; j < totalPackets -i -1; j++){

			if(IPHeaderSourceData(packet[j].iphdr.sourceIpAddr) >  IPHeaderSourceData(packet[j+1].iphdr.sourceIpAddr) ){
				wholePacket temp = packet[j];
				packet[j] = packet[j+1] ;
				packet[j+1] = temp;
			}
		}
    }

}

void sortPacketsAccordingToDestinationIPAddress(){

	for(int i=0 ; i< totalPackets -1; i++){
		for(int j=0 ; j < totalPackets -i -1; j++){
			if(IPHeaderSourceData(packet[j].iphdr.sourceIpAddr) ==  IPHeaderSourceData(packet[j+1].iphdr.sourceIpAddr) ){
				if(IPHeaderDestinationData(packet[j].iphdr.destIpAddr) >  IPHeaderDestinationData(packet[j+1].iphdr.destIpAddr) ){
					wholePacket temp = packet[j];
					packet[j] = packet[j+1] ;
					packet[j+1] = temp;
				}
			}
		}
    }

}

void sortPacketsAccordingToSourcePort(){

	for(int i=0 ; i< totalPackets -1; i++){
		for(int j=0 ; j < totalPackets -i -1; j++){
			if(IPHeaderSourceData(packet[j].iphdr.sourceIpAddr) ==  IPHeaderSourceData(packet[j+1].iphdr.sourceIpAddr) ){
				if(IPHeaderDestinationData(packet[j].iphdr.destIpAddr) == IPHeaderDestinationData(packet[j+1].iphdr.destIpAddr) ){
					if(sourcePortFromTcpHeader(packet[j].tcphdr.sourcePort) >  sourcePortFromTcpHeader(packet[j+1].tcphdr.sourcePort)){
						wholePacket temp = packet[j];
						packet[j] = packet[j+1] ;
						packet[j+1] = temp;
					}
				}
			}
		}
    }

}

void sortPacketsAccordingToDestinationPort(){

	 for(int i=0 ; i< totalPackets -1; i++){
		for(int j=0 ; j < totalPackets -i -1; j++){
			if(IPHeaderSourceData(packet[j].iphdr.sourceIpAddr) ==  IPHeaderSourceData(packet[j+1].iphdr.sourceIpAddr) ){
				if(IPHeaderDestinationData(packet[j].iphdr.destIpAddr) == IPHeaderDestinationData(packet[j+1].iphdr.destIpAddr) ){
					if(sourcePortFromTcpHeader(packet[j].tcphdr.sourcePort) ==  sourcePortFromTcpHeader(packet[j+1].tcphdr.sourcePort)){
						if(destPortFromTcpHeader(packet[j].tcphdr.destPort) >  destPortFromTcpHeader(packet[j+1].tcphdr.destPort)){
							wholePacket temp = packet[j];
							packet[j] = packet[j+1] ;
							packet[j+1] = temp;
						}
					}
				}
			}
		}
    }

}

void sortPacketsAccordingToSequenceNumber(){

	 for(int i=0 ; i< totalPackets -1; i++){
		for(int j=0 ; j < totalPackets -i -1; j++){
			if(IPHeaderSourceData(packet[j].iphdr.sourceIpAddr) ==  IPHeaderSourceData(packet[j+1].iphdr.sourceIpAddr) ){
				if(IPHeaderDestinationData(packet[j].iphdr.destIpAddr) == IPHeaderDestinationData(packet[j+1].iphdr.destIpAddr) ){
					if(sourcePortFromTcpHeader(packet[j].tcphdr.sourcePort) ==  sourcePortFromTcpHeader(packet[j+1].tcphdr.sourcePort)){
						if(destPortFromTcpHeader(packet[j].tcphdr.destPort) ==  destPortFromTcpHeader(packet[j+1].tcphdr.destPort)){
							if(sequenceNumber(packet[j].tcphdr.sequenceNumber) >  sequenceNumber(packet[j+1].tcphdr.sequenceNumber)){
								wholePacket temp = packet[j];
								packet[j] = packet[j+1] ;
								packet[j+1] = temp;
							}
						}
					}
				}
			}
		}
    }

}

void printNotable(int impCollectionCounter){

	for(int i=0 ; i < impCollectionCounter ; i++){
		printf("\nFor Notable %d : \n" , i+1);
		printf("Source Port = %lu\n" , notable[i].sourcePortData);
		printf("Destination Port = %lu\n" , notable[i].destPortData);
	}

}
int checkSeparateFilePackets(){

	int insCounter=1;
	int impCollectionCounter = 1;
	int tempCounter = 0;
	//int ct = 0 ;
	for(int i=0 ; i< totalPackets ; i++){
		if((int)packet[i].ethhdr.ethType[1] == 0){  //checking if its IP Header
			if( (int)packet[i].iphdr.protocol == 6 ) {   //checking if its TCP Header
				if(packet[i].dataPayloadSize != 0){
					if(IPHeaderSourceData(packet[i].iphdr.sourceIpAddr) !=  IPHeaderSourceData(packet[i+1].iphdr.sourceIpAddr)
						|| IPHeaderDestinationData(packet[i].iphdr.destIpAddr) != IPHeaderDestinationData(packet[i+1].iphdr.destIpAddr)
						|| sourcePortFromTcpHeader(packet[i].tcphdr.sourcePort) !=  sourcePortFromTcpHeader(packet[i+1].tcphdr.sourcePort)
						|| destPortFromTcpHeader(packet[i].tcphdr.destPort) !=  destPortFromTcpHeader(packet[i+1].tcphdr.destPort)){

						insCounter++;
						tempCounter = 0;
					}
					else {
						tempCounter++;
						if(tempCounter == 30){
							notable[impCollectionCounter-1].sourceIPData = IPHeaderSourceData(packet[i].iphdr.sourceIpAddr);
							notable[impCollectionCounter-1].destIPData = IPHeaderDestinationData(packet[i].iphdr.destIpAddr);
							notable[impCollectionCounter-1].sourcePortData = sourcePortFromTcpHeader(packet[i].tcphdr.sourcePort);
							notable[impCollectionCounter-1].destPortData = destPortFromTcpHeader(packet[i].tcphdr.destPort);
							impCollectionCounter++;
						}
					}
				}
			}
		}
	}
	//printNotable(impCollectionCounter);
	printf("\nThere are %d separate connections in this PCAP Data File.\nOf which %d are important and noticeable.\n" , insCounter , impCollectionCounter);
	return impCollectionCounter;

}

void printAllDataPayload(int counter, int len ,FILE *fp , FILE *segment){

	unsigned char ch;
	int ct = 0 ;
	int j=0;
	//fprintf(segment, "\n\n------------------DATA Payload for Packet No : %d  ---------------------\n\n", counter +1);

	while(len--) {
		j++;
		fread(&ch,1,1,fp);
	//	printf("%.02x " , ch&(0xff));

		//writeDataPayLoadInFile();

		packet[counter].data[ct] = ch;

		if(isprint(ch)) {
			fputc( ch ,segment);
		}
		else {
			fputs(".", segment);
		}

		//if(j%8==0) cout << "   " ;
		if(j%16==0) {
			//cout << endl;
			j=0;
		}
		ct++;
	}
}

void loadDataPayload(int counter, int len ,FILE *fp ){

	unsigned char ch;
	int j=0;
	int ct = 0;

	while(len--) {
		j++;
		fread(&ch,1,1,fp);
		packet[counter].data[ct] = ch;
		ct++;
	}
}

void printAllDataPayloadAndWriteinFileAsTxt(int counter, int len ,FILE *fp , FILE *segment){

	unsigned char ch;
	int ct = 0 ;
	int j=0;
	fprintf(segment, "\n\n------------------DATA Payload for Packet No : %d  ---------------------\n\n", counter +1);

	while(len--) {
		j++;
		fread(&ch,1,1,fp);
	//	printf("%.02x " , ch&(0xff));

		//writeDataPayLoadInFile();

		packet[counter].data[ct] = ch;

		if(isprint(ch)) {
			fputc( ch ,segment);
		}
		else {
			fputs(".", segment);
		}

		//if(j%8==0) cout << "   " ;
		if(j%16==0) {
			//cout << endl;
			j=0;
		}
		ct++;
	}
}


int readHeadersFromPcapFile(int len,FILE *fp , int counter ){

	fread(&packet[counter].ethhdr , sizeof(struct ethernetHeader) , 1 , fp);  // Reading etherNet Header
	//packet[counter].ethhdr = tempEthHdr;

	len = len - sizeof(struct ethernetHeader); // subtracting ethernet header size
											   // from length .
	//cout << endl <<(int)ethhdr.ethType[1] <<endl;

	if((int)packet[counter].ethhdr.ethType[1] == 0){    //check the ethernet type . 0 means IPV4 and 6 means ARP
		fread(&packet[counter].iphdr , sizeof(struct IPHeader) , 1 , fp);
		len = len - sizeof(struct IPHeader);	   // subtracting IP header size
												   // from length .
		//cout << endl <<(int)iphdr.protocol <<endl;

		if( (int)packet[counter].iphdr.protocol == 6 ){	// Check protocol ; 6 means TCP , 17 Means UDP
			fread(&packet[counter].tcphdr , sizeof(struct TCPHeader) , 1 , fp);
			len = len - sizeof(struct TCPHeader);  // subtracting TCP header size
												   // from length .
		}
		else if( (int)packet[counter].iphdr.protocol == 17 ){
			fread(&packet[counter].udphdr , sizeof(struct UDPHeader) , 1 , fp);
			len = len - sizeof(struct UDPHeader);  // subtracting UDP header size
												   // from length .
		}

	}
	else if((int)packet[counter].ethhdr.ethType[1] == 6){			//check the ethernet type . 0 means IPV4 and 6 means ARP
		fread(&packet[counter].arphdr , sizeof(struct ARPHeader) , 1 , fp);
		len = len - sizeof(struct ARPHeader);	   // subtracting  ARP header size
												   // from length .
	}

	return len;
}

void separatingIndividualPacketsToAppropriateFiles(){

	sortPacketsAccordingToSourceIPAddress();
	sortPacketsAccordingToDestinationIPAddress();
	sortPacketsAccordingToSourcePort();
	sortPacketsAccordingToDestinationPort();
	sortPacketsAccordingToSequenceNumber();

}

void printAllPacketInformations(){

    for(int k = 0 ; k< totalPackets ; k++){
        cout <<"\nPacket no : " << k+1 << " and Source IP Address : " <<  (int)packet[k].iphdr.sourceIpAddr[0]  << 
        "."  << (int)packet[k].iphdr.sourceIpAddr[1] << "." << (int)packet[k].iphdr.sourceIpAddr[2] << "." <<  
        (int)packet[k].iphdr.sourceIpAddr[3]<< " and Destination IP Address : " << (int)packet[k].iphdr.destIpAddr[0] << "."
		<< (int)packet[k].iphdr.destIpAddr[1] << "." << (int)packet[k].iphdr.destIpAddr[2] << "." << (int)packet[k].iphdr.destIpAddr[3] <<endl;
        //cout <<"\n\nPacket no : " << k+1 << " and Destination port : " <<  IPHeaderDestinationData(iphdr[k]) <<endl <<endl;
        cout <<"\nPacket no : " << k+1 << " and Source port : " <<  sourcePortFromTcpHeader(packet[k].tcphdr.sourcePort)
        << " and Destination port : " <<  destPortFromTcpHeader(packet[k].tcphdr.destPort) <<endl;
        cout <<"\nPacket no : " << k+1 << " and Sequence Number : " <<  sequenceNumber(packet[k].tcphdr.sequenceNumber) <<endl ;
        //cout <<"\n\nPacket no : " << k+1 << " and Source port : " <<  sourceIPAdressDataArray[k] <<endl <<endl;
    }
}

void writeAllDataPayloadInFile(FILE *fp , int counter){

	printf("Enter a file name to save Data payload from all packets.\n");
	string s;
	string txtExtension= ".txt";
	cin >> s;
	s += txtExtension;
	cout << "The file name you have given is : " << s << endl ;
		
	char file[200];
	for(int j =0 ;  ; j++ ){

		file[j] = s[j];
		if(s[j] == '\0'){
			 file[j] = '\0';
			 break;
		}
	}

	FILE *segment;
	segment = fopen(file ,"w");

	pcapGlobalHeader globhdr;
	fread(&globhdr, sizeof(struct pcapGlobalHeader), 1, fp);
			
	//cout <<"----------DATA Payload For Individual Packets----------- " << endl <<endl;
	fprintf(segment , "----------DATA Payload For Individual Packets-----------\n\n ");
			
	while(1){
		packetHeader  pachdr;

		fread(&pachdr , sizeof(struct packetHeader) , 1 , fp);
		if(feof(fp)) break;

		int len = dataSize(pachdr) ;
		//cout <<"\n\nPacket no : " << counter << " and Packet size : " <<  len <<endl <<endl;

		len = readHeadersFromPcapFile(len , fp , counter);
		packet[counter].dataPayloadSize = len;
				
		//cout <<"\n\nPacket no : " << counter << " and Data Payload size : " <<  dataPayloadSize[counter] <<endl <<endl;

		//printAllDataPayload(counter ,len , fp , segment);

		printAllDataPayloadAndWriteinFileAsTxt(counter, len ,fp , segment);

		counter++;
		//if (counter>1) break;  //control how many packets will be shown or read.

	}
			
	totalPackets = counter;

	cout << "Total packets = " << totalPackets <<endl;
	
	printf("\nData payload for all packets have been written in file successfully.\n\n");

	fclose(segment);

}

void analysePCAPfile(){

	cout << "\nEnter a existing pcap filename to examine .(Have to be a pcap file). "  << endl;
		
	FILE *fp;

	unsigned char ch;
	unsigned char str[16];
	string s;
	string pcapExtension= ".pcap";
	cin >> s;
	s += pcapExtension;
	cout << "The file name you have given is : " << s << endl << endl;
		
	char file[200];
	for(int j =0 ;  ; j++ ){
		file[j] = s[j];
		if(s[j] == '\0'){
			 file[j] = '\0';
			 break;
		}
	}	
			
	while(1){

		cout << "What you want to do with the PCAP file? \n----The Options are-----\n" << endl; 
		cout << "Option 1 : Separate the different connections from the Pcap file and write  it in text file." << endl;
		cout << "Option 2 : Read and write the full Pcap File in Hexadecimal , Character and Integers and Print it on the Screen and in text file ." <<endl;
		cout << "Option 3 : Write the data payloads from all the packets in file. "<<endl;
		cout << "\t   Additionally read and count the packet numbers . " <<endl;
	
		int choice2 = 0;
		int counter=0;
		
		cout << "Choose Option :  " ;
		cin >> choice2;
	
		if(choice2 == 1){
	
			fp = fopen(file,"rb");
			pcapGlobalHeader globhdr;
			fread(&globhdr, sizeof(struct pcapGlobalHeader), 1, fp);

			while(1){

				packetHeader  pachdr;

				fread(&pachdr , sizeof(struct packetHeader) , 1 , fp);
				if(feof(fp)) break;

				int len = dataSize(pachdr) ;
				len = readHeadersFromPcapFile(len , fp , counter);

				packet[counter].dataPayloadSize = len;
				loadDataPayload(counter, len ,fp );
				
				counter++;
			}

			totalPackets = counter;
			cout << "\n\nTotal packets = " << totalPackets <<endl;

			fclose(fp);

			for(int i=0 ; i < totalPackets ; i++){

				int len = dataSizeForIPHeader( packet[i].iphdr.ipLength );
			   	//cout <<"\n\nPacket no : " << i+1 << " and Packet size : " <<  len <<endl <<endl;
				//cout <<"\n\nPacket no : " << i+1 << " and Packet payload : " <<  packet[i].dataPayloadSize <<endl <<endl;

			}

			//printfDataArray(counter);

			FILE *dataSegment;
			//dataSegment = fopen("dataFile.txt" , "w");
		/*
			for(int i=0 ; i< totalPackets ; i++){
				cout <<"\n\nPacket no : " << i+1 << " and Source IP : " ;

				for(int j =0 ; j< 4 ; j++){

					cout << (int)packet[i].iphdr.sourceIpAddr[j]  << "." ;

				}

				cout << endl <<endl;

			}

		*/

			separatingIndividualPacketsToAppropriateFiles();

			int instanceCounter = checkSeparateFilePackets();

			printf( "\n\nTotal Separate Files in this PCAP file is %d . \n\n" , instanceCounter);

			//printf("\nEnter File name you want to create . \n");

			string fileName[instanceCounter];

			for(int i=0 ; i< instanceCounter ; i++){
				printf("\nEnter File name for FILE NO : %d \n" , i+1);
				string s;
				string txtExtension= ".txt";
				cin >> s;
				s += txtExtension;

				fileName[i] = s;
			}
			
			cout << "The data file names you have given are : " << endl << endl;
			for(int i=0 ; i< instanceCounter ; i++){

				 cout << fileName[i]  << "   " ;
			}
			cout << endl;

			//printAllPacketInformations();

			char nameFile[200];
			for(int j =0 ;  ; j++ ){

				nameFile[j] = fileName[0][j];
				if(fileName[0][j] == '\0') {
					nameFile[j] = '\0';
					break;
				}
			}
			//cout <<endl<<endl;
			/*
			for(int j =0 ; j<fileName[0].length() ; j++ ){
				printf("%c" , nameFile[j]);
			}

			cout <<endl<<endl;
			*/
			dataSegment = fopen( nameFile , "w+");

			fprintf(dataSegment , "-----------Collected Full Data File : %d -----\n\n" , 1);
			//cout << "paisi 0 \n\n" ; 

			int ct=1;
			for(int i=0 ; i< totalPackets ; i++){
				//unsigned long int sqNumber = sequenceNumber(packet[i].tcphdr.sequenceNumber);
				if((int)packet[i].ethhdr.ethType[1] == 0){  //checking if its IP Header
					if( (int)packet[i].iphdr.protocol == 6 ) {   //checking if its TCP Header
						if(packet[i].dataPayloadSize != 0){   // checks if data payload is empty or not
							//if(sqNumber + packet[i].dataPayloadSize == sequenceNumber(packet[i+1].tcphdr.sequenceNumber)){ // check if the next sequence is valid
								//fprintf(dataSegment, "\n\n----------DATA Payload for Packet No : %d  PayloadSize = %d  -----------\n\n", i+1 , packet[i].dataPayloadSize );
								//cout <<"\n\nPacket no : " << i+1 << " and Data Payload size : " <<  dataPayloadSize[i] <<endl <<endl;
								//cout <<"\n\nPacket no : " << i+1 << " and Source port : " <<  dataSizeForTCPHeader(tcphdr[i]) <<endl <<endl;
								//cout <<"\n\nPacket no : " << i+1 << " and Time to leave : " <<  (int)iphdr[i].TTL <<endl <<endl;

								for(int j =0 ; j< packet[i].dataPayloadSize ; j++){

									ch = packet[i].data[j];
									//printf("%.02x " , ch&(0xff));
									if(isprint(ch)) {
										fputc( ch ,dataSegment);
									}
									else {
										if(ch == '\n' ) fputs("\n", dataSegment);
										else fputs(".", dataSegment);
									}
								}

							//}
							if(i==totalPackets-1) break; //total
							if(IPHeaderSourceData(packet[i+1].iphdr.sourceIpAddr) ==  notable[ct-1].sourceIPData
								&& IPHeaderDestinationData(packet[i+1].iphdr.destIpAddr) == notable[ct-1].destIPData
								&& sourcePortFromTcpHeader(packet[i+1].tcphdr.sourcePort) ==  notable[ct-1].sourcePortData
								&& destPortFromTcpHeader(packet[i+1].tcphdr.destPort) ==  notable[ct-1].destPortData ){


								fclose(dataSegment);
								//cout << "paisi  ct = " << ct  << "\n\n";
								char file[200];
								for(int j =0 ;  ; j++ ){

									file[j] = fileName[ct][j];
									if(fileName[ct][j] == '\0') {
										file[j] = '\0';
										break;
									}
								}
		/*

								for(int j =0 ; j<=fileName[ct].length() ; j++ ){
									printf("%c" , file[j]);
								}
								cout <<endl<<endl;
		*/
								dataSegment = fopen( file , "w+");
								ct++;

								fprintf(dataSegment , "-----------Collected Full Data File : %d -----\n\n" , ct);
							}
						}
					}
				}
			}
			//cout << "paisi  ct = " << ct  << "\n\n";
			//cout << "\n\nTotal packets = " << totalPackets <<endl;
			fclose(dataSegment);
			//fclose(fp);
			printf("\nSuccessfully created separate Text files that contains the packet data for important connections. \n\n");
		}
			
		else if (choice2 == 2) {
			fp = fopen(file,"rb");
			readAndWriteFullPcapDataAsCharacterAndInteger( fp );
			fclose(fp);
		}
			
		else if (choice2 == 3) {
	
			fp = fopen(file,"rb");
			writeAllDataPayloadInFile(fp , counter);
			fclose(fp);
				
		}
		cout << "Do you want to choose another option? (Yes/No)" <<endl;
	
		string s2;
		cin >> s2;
			
		cout << endl<<endl;
		if(s2 == "No" || s2 == "NO" || s2 == "no")	break;
		else if(s2 == "Yes" || s2 == "yes" || s2 == "YES") 	continue;
		else {
	
			printf("You have given an invalid option.....Terminating process\n\n");
			exit(0);
		}
		
	}
}

int main(){

	while(1){
		
		int choice =0;

		cout << "\nWhat do you want to do ?" <<endl;
		cout << "Choice 1 : Capture Raw data Packets using Socket .(Only capture TCP Packets)" <<endl;
		cout << "Choice 2 : Analyse a existing PCAP File . "<<endl;
	
		cout << "Enter your choice :  " ;
		cin >> choice;

		if(choice == 1) packetCapture();

		if(choice == 2){
			analysePCAPfile();
		}
		
		cout << "Do you want to repeat the process? (Yes/No)" <<endl;
	
		string s1;
		cin >> s1;
		
		cout << endl << endl;
		if(s1 == "No" || s1 == "NO" || s1 == "no")	break;
		else if(s1 == "Yes" || s1 == "yes" || s1 == "YES") 	continue;
		else {
			printf("You have given an invalid option.....Terminating process\n\n");
			exit(0);
		}
	
	}

}
