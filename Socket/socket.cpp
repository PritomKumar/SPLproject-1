#include<stdio.h>
#include <bits/stdc++.h>
#include <sys/socket.h>

using namespace std;

#define ETH_P_ALL   0x0003 

#if BYTE_ORDER == BIG_ENDIAN
#define htons(n)
#else 
#define htons(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))
#endif ///converting host byte order..

FILE *logfile;
int sock_raw;

int PrintHex(unsigned char c, int i) {
  if (i == 0 ) {
    //printf("%06X  ", i);
    printf("\n");
  } 
  else {
    if (i%16 == 0)
      //printf("\n%06X  ", i);
       printf("\n");
     
    else if (i%16 == 8)
      printf(" -- ");
    else
      printf(" ");
  }    

  printf("%02X", c);
  return 0;
}


int main(){

	sock_raw = socket( AF_PACKET , SOCK_RAW ,htons(ETH_P_ALL)) ;
	 
	long long int totalDataSize = 0;        //holds the total data of every packets
    long long int packetNumber = 1; 

    int saddr_size , data_size;
    struct sockaddr saddr;                  
    
    unsigned char buffer[100000];           //holds the packet while capturing through socket
    
    saddr_size = sizeof(saddr);
	 
	for(int i=0;i<10;i++)
	 {
		
	    data_size = recvfrom(sock_raw , buffer ,  100000, 0 , &saddr , (socklen_t*)&saddr_size);
		/*
		for(int j=0 ; j < data_size ; j++){
		
			unsigned char *pk ;
			pk = buffer;
			
			PrintHex(*pk++ , j); 
			
			
			
		}
*/

		for(int j=0;j<data_size;j++){
             if (j%16 == 0)
			   printf("\n");
			 
			else if (j%16 == 8)
			  printf(" -- ");
			else
			  printf(" ");
            printf("%.02X ", buffer[j]);
        }
        
		//fwrite(&buffer,sizeof(unsigned char )*buflen,1,iFile);
		
		printf("\nSocket reading for Packet %d----- packet size %d \n" ,i+1 ,data_size );
		
		
	}


}
