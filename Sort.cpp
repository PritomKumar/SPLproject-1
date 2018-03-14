#include<stdio.h>
#include<iostream>

using namespace std;

struct check{

    int a;
    int b;

};

int main(){

    int n=9;
    check test[n];

    test[0].a = 10;
    test[1].a = 15;
    test[2].a = 8;
    test[3].a = 50;
    test[4].a = 10;
    test[5].a = 15;
    test[6].a = 50;
    test[7].a = 50;
    test[8].a = 50;

    for(int i=0 ; i< n ; i++){

        test[i].b = (i+1)*10;
    }

    int tarray[n];

    for(int i=0 ; i< n ; i++){

        tarray[i] = -1;
    }

    int ct2 =0;

    for(int i=0 ; i< n ; i++){
        int ct=0;

        for(int j=0 ; j< n ; j++){
            if(test[i].a != tarray[j]){
                ct++;
            }
        }
        if(ct == n) {
            tarray[ct2] = test[i].a;
            ct2++;
        }
    }

    for(int i=0 ; i< ct2-1 ;i++){
        for(int j=0 ; j< ct2-i-1 ; j++){
            if(tarray[j]>tarray[j+1]){

                int temp = tarray[j];
                tarray[j] =tarray[j+1];
                tarray[j+1] = temp;
            }

        }
    }
/*
    for(int i=0 ; i< n ; i++){
        cout << tarray[i] << " ";
    }
*/

    check temp[n];
    int ct=0;

    for(int i=0 ; i< ct2 ; i++){

        for(int j=0 ; j< n ; j++){
            if(tarray[i]== test[j].a){
                temp[ct] = test[j];
                ct++;
            }
        }
    }

    for(int i=0 ; i< n ; i++){
         test[i]=temp[i];
    }
    for(int i=0 ; i< n ; i++){
        cout << test[i].a << " ";
    }

}
