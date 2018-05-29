#include<iostream>
#include<string.h>
#include<stdio.h>
#include "pcapAnalyze.cpp"

using namespace std;

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
