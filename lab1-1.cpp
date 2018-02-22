#include <iostream>
#include <fstream>
#include <cmath>
#include <queue>
#include <string>
#include <vector>
#include <algorithm>

using namespace std;

int **adjacencyMatrix;
int numberOfVertex;
int connection;
int dead;

string arr = "SABCDEFG";
string col = "WGB";


string *str;

void makeAdjacencyMatrix()
{
	adjacencyMatrix = new int *[numberOfVertex];
	for(int i=0; i<numberOfVertex; i++)
	{
		adjacencyMatrix[i] = new int [numberOfVertex];
	}
	str = new string [numberOfVertex];
}

void destroyAdjacencyMatrix()
{
	for(int i=0; i<numberOfVertex; i++)
	{
		delete [] adjacencyMatrix[i];
	}
	delete [] adjacencyMatrix;

}

bool openFile(char *fileName)
{
	ifstream iFile;
	iFile.open(fileName);
	if(iFile.is_open())
	{
	    //cout << "pailam tore" <<endl;
		iFile >> numberOfVertex;

		makeAdjacencyMatrix();

		for (int i=0 ; i< numberOfVertex ;i++){
            for(int j=0 ; j< numberOfVertex ; j++){
                adjacencyMatrix[i][j] =0 ;
            }
		}
		//cout << "pailam tore" <<endl;

		int i=0;
        string lel;
        //cout << "pailam tore" <<endl;
        getline(iFile,lel);

        while ( i<numberOfVertex){

            iFile >> str[i];
            i++;
        }
       // cout << "pailam tore" <<endl;
        iFile >> connection ;
       // getline(iFile,lel);

        string b1 ,b2;

        for(int i=0; i < connection ; i++ ){
            iFile >> b1 >>b2;

            for (int j=0 ; j< numberOfVertex ;j++){
                if(str[j] == b1){
                     for(int k =0 ; k < numberOfVertex ; k++){
                        if (str[k] == b2){
                            adjacencyMatrix[j][k] = 1;
                        }
                     }
                }
            }
        }/*
        for (int i=0 ; i< numberOfVertex ;i++){
            for(int j=0 ; j< numberOfVertex ; j++ ) {
                cout << adjacencyMatrix[i][j] << " " ;
            }
        cout <<endl;
    }
    */

        //iFile >> dead;
		iFile.close();

		return true;
	}
	else
	{
		cout << "coud not open input file" << endl;
		return false;
	}

}

void dfsVisit(int *color, int &time, int *prev, int *d, int *f, int u)
{
	color[u]=1;
	time++;
	d[u]=time;
	for(int v=0; v<numberOfVertex; v++)
	{
		if(adjacencyMatrix[u][v]==1)
		{
			if(color[v]==0)
			{
				prev[v]=u;
				dfsVisit(color, time, prev, d, f, v);
			}
		}
	}
	color[u]=2;
	time++;
	f[u]= time;
}

void dfs(int *color, int &time, int *prev, int *d, int *f)
{
	for(int u=0; u<numberOfVertex; u++)
	{
		color[u]=0;
		prev[u]=-1;//-1 for NULL
		f[u] = (int) pow(2,31)-10;
		d[u] = (int) pow(2,31)-10;
	}

	for(int u=0; u<numberOfVertex; u++)
	{
		if(color[u]==0) dfsVisit(color, time, prev, d, f, u);
	}
}


void printResult(int *color, int *prev, int *d, int*f)
{

	for(int i=0; i<numberOfVertex; i++)
	{
		cout 	<< arr[i] << "\t"
				<< col[color[i]] << "\t"
				<< d[i] << "\t"
				<< f[i] << "\t"
				<< arr[prev[i]] << endl;
	}
}

struct Pair
{
	int f;
	string item;
};

bool sortingRule (Pair i, Pair j)
{
	return i.f > j.f;
}

void printResultForTopological(int *color, int *prev, int *d, int*f)
{
	//string arr[9] = {"Shirt", "Tie", "Jacket", "ug", "pant", "belt", "socks", "shoe", "watch"};

	vector <Pair> pairVec;
	string *ll;
	ll= new string [numberOfVertex];

	for(int i=0; i<numberOfVertex; i++)
	{
		Pair temp;
		temp.f = f[i];
		temp.item = str[i];

		pairVec.push_back(temp);
	}
    int l=1;
	sort(pairVec.begin(), pairVec.end(), sortingRule);

    cout << "Case #" << l << ": Dilbert should drink beverages in the order : ";
	for(int i=0; i<numberOfVertex; i++)
	{
		cout << pairVec[i].item << "\t";
	}
	cout << endl;
	l++;
}

int main (int argc, char *argv[])
{
	if(!openFile("adj.txt")) return -1;

	int *color, *prev, *d, *f, time =0;
	//color =0-white, =1-grey, =2-black

	color = new int [numberOfVertex];
	prev = new int [numberOfVertex];
	d = new int [numberOfVertex];
	f = new int [numberOfVertex];


	//dfs(color, time, prev, d, f);

	//printResult(color, prev, d, f);

	for (int i=0 ; i< numberOfVertex ;i++){
        for(int j=0 ; j< numberOfVertex ; j++ ) {
            cout << adjacencyMatrix[i][j] << " " ;
        }
        cout <<endl;
    }


	printResultForTopological(color, prev, d, f);

	delete [] f;
	delete [] d;
	delete [] prev;
	delete [] color;
	destroyAdjacencyMatrix();
	return 0;
}

