#include <stdio.h>
#include <stdlib.h> // malloc
#include <string.h> // strdup, strcmp

#define SORT_BY_WORD	0 // 단어 순 정렬
#define SORT_BY_FREQ	1 // 빈도 순 정렬

// User structure type definition
// 단어 구조체
typedef struct {
	char	*word;		// 단어
	int		freq;		// 빈도
} tWord;

////////////////////////////////////////////////////////////////////////////////
// LIST type definition
typedef struct node
{
	tWord		*dataPtr;
	struct node	*link; // 단어순 리스트를 위한 포인터
	struct node	*link2; // 빈도순 리스트를 위한 포인터
} NODE;

typedef struct
{
	int		count;
	NODE	*head; // 단어순 리스트의 첫번째 노드에 대한 포인터
	NODE	*head2; // 빈도순 리스트의 첫번째 노드에 대한 포인터
} LIST;

////////////////////////////////////////////////////////////////////////////////
// Prototype declarations

// Allocates dynamic memory for a list head node and returns its address to caller
// return	head node pointer
// 			NULL if overflow
// 리스트의 헤드 노드를 만드는 함수, 메모리를 동적으로 할당 후 할당된 주소 반환
LIST *createList(void);

//  단어 리스트에 할당된 메모리를 해제 (head node, data node, word data)
void destroyList( LIST *pList);

// internal search function
// searches list and passes back address of node containing target and its logical predecessor
// for update_dic function
// return	1 found
// 			0 not found
static int _search( LIST *pList, NODE **pPre, NODE **pLoc, tWord *pArgu);

static int _search_by_freq( LIST *pList, NODE **pPre, NODE **pLoc, tWord *pArgu);

// internal insert function
// inserts data into a new node
// for update_dic function
// return	1 if successful
// 			0 if memory overflow
static int _insert( LIST *pList, NODE *pPre, tWord *dataInPtr);

// 단어를 사전에 저장
// 새로 등장한 단어는 사전에 추가
// 이미 사전에 존재하는(저장된) 단어는 해당 단어의 빈도를 갱신(update)
void update_dic( LIST *list, char *word);

// internal function
// for connect_by_frequency function
// connects node into a frequency list
static void _link_by_freq( LIST *pList, NODE *pPre, NODE *pLoc);

// 단어순 리스트를 순회하며 빈도순 리스트로 연결
void connect_by_frequency( LIST *list);

// 사전을 화면에 출력 ("단어\t빈도" 형식)
void print_dic( LIST *pList); // 단어순
void print_dic_by_freq( LIST *pList); // 빈도순

// 단어 구조체를 위한 메모리를 할당하고 word, freq 초기화
// for update_dic function
// return	할당된 단어 구조체에 대한 pointer
//			NULL if overflow
tWord *createWord( char *word);

//  단어 구조체에 할당된 메모리를 해제
// for destroyList function
void destroyWord( tWord *pNode);

////////////////////////////////////////////////////////////////////////////////
// compares two words in word structures
// for _search function
// 정렬 기준 : 단어
int compare_by_word( const void *n1, const void *n2)
{
	tWord *p1 = (tWord *)n1;
	tWord *p2 = (tWord *)n2;
	
	return strcmp( p1->word, p2->word);
}
////////////////////////////////////////////////////////////////////////////////
// for _search_by_freq function
// 정렬 기준 : 빈도 내림차순(1순위), 단어(2순위)
int compare_by_freq( const void *n1, const void *n2)
{
	tWord *p1 = (tWord *)n1;
	tWord *p2 = (tWord *)n2;
	
	int ret = (int) p2->freq - p1->freq;
	
	if (ret != 0) return ret;
	
	return strcmp( p1->word, p2->word);
}


////////////////////////////////////////////////////////////////////////////////
int main( int argc, char **argv)
{
	LIST *list;
	int option;
	FILE *fp;
	char word[1000];
	
	if (argc != 3)
	{
		fprintf( stderr, "Usage: %s option FILE\n\n", argv[0]);
		fprintf( stderr, "option\n\t-n\t\tsort by word\n\t-f\t\tsort by frequency\n");
		return 1;
	}

	if (strcmp( argv[1], "-n") == 0) option = SORT_BY_WORD;
	else if (strcmp( argv[1], "-f") == 0) option = SORT_BY_FREQ;
	else {
		fprintf( stderr, "unknown option : %s\n", argv[1]);
		return 1;
	}

	// creates an empty list
	list = createList();
	
	if (!list)
	{
		printf( "Cannot create list\n");
		return 100;
	}

	if ((fp = fopen( argv[2], "r")) == NULL) 
	{
		fprintf( stderr, "cannot open file : %s\n", argv[2]);
		return 1;
	}
	
	while(fscanf( fp, "%s", word) != EOF)
	{
		// 사전(단어순 리스트) 업데이트
		update_dic( list, word);
	}
	
	fclose( fp);

	if (option == SORT_BY_WORD) {
		
		// 단어순 리스트를 화면에 출력
		print_dic( list);
	}
	else { // SORT_BY_FREQ
	
		// 빈도순 리스트 연결
		connect_by_frequency( list);
		
		// 빈도순 리스트를 화면에 출력
		print_dic_by_freq( list);
	}
	
	// 단어 리스트 메모리 해제
	destroyList( list);
	
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
LIST *createList(void)
{
	LIST *listheader = (LIST *)malloc(sizeof(LIST));
	if (listheader == NULL) {
		printf("Memory allocation failled!");
		return NULL;
	}

	listheader->count = 0;
	listheader->head = NULL;
	listheader->head2 = NULL;

	return listheader;
}

//  단어 리스트에 할당된 메모리를 해제 (head node, data node, word data)
void destroyList( LIST *pList) {
    if (pList == NULL) return;

    NODE *temp = pList->head;
    NODE *next;

    while (temp != NULL) {
        next = temp->link; 
        destroyWord(temp->dataPtr);  
        free(temp);  
        temp = next;  
    }
    free(pList);
}

/* 
내부 서치 함수. pLoc과 pPre를 사용해서 리스트를 순회하며 pArgu의 자리를 찾음.
리스트에 존재하면 1을 반환하고 없으면 0을 반환함.
search의 인자에 **pPre, **pLoc으로 오는 이유는 포인터의 주소를 받아오는 것이기 때문.
서치 함수 내부에서 pPre, pLoc 사용할 때 *을 붙이는 것은 
pPre와 pLoc에 저장된 각 NODE들의 주소가 서치 함수에서 사용되기 때문임.
새로운 단어 노드를 삽입할 위치는 pPre의 다음임. 
*/
static int _search( LIST *pList, NODE **pPre, NODE **pLoc, tWord *pArgu)
{
	*pPre = NULL;
	*pLoc = pList->head;

	while (*pLoc != NULL && compare_by_word(pArgu, (*pLoc)->dataPtr) > 0) { // pArgu가 (*pLoc)->dataPtr 보다 사전적으로 뒤에 있는 경우
		*pPre = *pLoc; // pLoc을 다음 리스트의 노드로 옮기는 과정임.
		*pLoc = (*pLoc)->link;
	}

	if (*pLoc != NULL && compare_by_word(pArgu, (*pLoc)->dataPtr) == 0) // 리스트에 이미 단어가 존재하는 경우
        return 1; // Found
    else
        return 0; // Not found
}

/*
서치 함수에서 찾은 위치인 pPre의 다음 위치 (=pLoc)에 새로운 단어노드를 삽입하는 함수
인자로 pLoc이 아니라 pPre가 오는 이유는 새로 삽입되는 단어노드가 pPre와의 노드 연산을 통해 리스트에 삽입 될 수 있기 때문.
*/
static int _insert( LIST *pList, NODE *pPre, tWord *dataInPtr)
{
	NODE *pNew = (NODE *)malloc(sizeof(NODE)); // 새로운 단어노드 선언 및 할당
	if (!pNew) return 0; 

	pNew->dataPtr = dataInPtr; //새 단어노드에 리스트에 추가할 단어 저장
	pNew->link = NULL;	

	if (pPre == NULL) { // 리스트의 시작에 삽입
        pNew->link = pList->head;
        pList->head = pNew;
    } else { // 중간이나 끝에 삽입
        pNew->link = pPre->link; // 새로운 단어노드의 link가 pLoc을 가리키게 함.
        pPre->link = pNew; // pPre의 link가 새로운 단어노드를 가리키게 함. 
		// pPre - pLoc 에서 pPre - pNew - pLoc 로 됨. 
    }

	pList->count += 1;
	return 1;
}

/*
main 함수에서 호출되는 함수임. 
words.txt 파일에서 한줄씩 읽어서 word로 전달.
search 함수로 리스트에 이미 있는 단어면 빈도만 += 1, 없으면 insert 함수로 삽입.
*/
void update_dic( LIST *list, char *word)
{
	NODE *pPre = NULL;
	NODE *pLoc = NULL;
	char *buffer = strdup(word); // word를 직접 건들여서 발생할 수 있는 문제 방지, 단 할당된 메모리 해제 필수.
	tWord *input = createWord(buffer); // buffer 단어 저장할 tWord 구조체 선언 및 할당.

	int found = _search(list, &pPre, &pLoc, input);

	if (found) {
		pLoc->dataPtr->freq += 1;
	}
	else {
		if(!_insert(list, pPre, input)) {
			printf("insertion failed!");
			exit(1);
		}
	}
	free(buffer);
}

/*
단어의 빈도에 따라 노드를 적절한 위치에 배치하기 위해 리스트를 검색

매개변수
LIST *pList: 조작되는 리스트에 대한 포인터.
NODE **pPre: 대상 위치 바로 이전 노드를 추적하는 더블 포인터.
NODE **pLoc: 함수가 리스트를 순회할 때 현재 위치를 추적하는 더블 포인터.
tWord *pArgu: 리스트에 배치될 노드의 데이터(단어)에 대한 포인터.

반환값
pArgu와 동일한 빈도를 가진 노드가 발견되면 1을 반환하고, 그렇지 않으면 0을 반환합니다.
*/
static int _search_by_freq(LIST *pList, NODE **pPre, NODE **pLoc, tWord *pArgu) {
    while (*pLoc != NULL && compare_by_freq(pArgu, (*pLoc)->dataPtr) > 0) //(*pLoc)->dataPtr의 빈도가 pArgu의 빈도보다 많을 경우 True
	{
		*pPre = *pLoc;
		*pLoc = (*pLoc)->link2;
	}
	if (*pLoc != NULL && compare_by_freq(pArgu, (*pLoc)->dataPtr) == 0) {
		return 1;
	}
	else {
		return 0 ;
	}
	
}

/*
매개변수
LIST *pList: 조작되는 리스트에 대한 포인터.
NODE *pPre: 삽입 지점 바로 앞의 노드에 대한 포인터.
NODE *pLoc: 삽입될 노드에 대한 포인터.

작동 과정
pPre가 NULL인 경우, 리스트의 시작 부분에 삽입.
그렇지 않으면 pPre 뒤에 노드를 삽입.
*/
static void _link_by_freq(LIST *pList, NODE *pPre, NODE *pLoc) {
    if (pPre == NULL) {
        // 빈도별 정렬된 리스트의 시작 부분에 삽입
        pLoc->link2 = pList->head2;  // 빈도 리스트의 현재 첫 번째 노드
        pList->head2 = pLoc;         // `pLoc`이 빈도 리스트의 새로운 헤드
    }
    else {
        // 빈도별 정렬된 리스트에서 `pPre` 뒤에 삽입
        pLoc->link2 = pPre->link2;  // `pLoc`은 `pPre`가 가리키던 것을 가리켜야 함
        pPre->link2 = pLoc;         // `pPre`는 `pLoc`을 가리킴
    }
}




/*
단어 기준으로 정렬된 리스트를 순회하며 link2를 사용해 빈도순 리스트로 연결함.
내부에서 _search_by_freq와 _link_by_freq 함수 사용.

매개변수
LIST *list: 단어별로 정렬된 노드를 포함하는 리스트에 대한 포인터.

과정
단어별로 정렬된 리스트(head)의 각 노드를 순회하며, 빈도별로 정렬된 리스트(head2)에서 올바른 위치를 찾고 연결.
*/
void connect_by_frequency(LIST *list) {
    NODE *pPre = NULL; // 빈도 기준으로 정렬된 리스트(list->head2)에서 삽입할 위치를 결정할 때, 삽입될 위치 바로 앞의 노드를 가리키는 포인터
    NODE *pLoc = NULL; // 빈도 기준으로 정렬된 리스트에서 새 노드(current)가 삽입될 위치를 추적하는 포인터
    NODE *current = list->head; // 원본 리스트(list->head)를 순회하는 동안 현재 노드의 위치를 추적하는 포인터

    while (current != NULL) {
        pPre = NULL;
        pLoc = list->head2;
        _search_by_freq(list, &pPre, &pLoc, current->dataPtr);
        _link_by_freq(list, pPre, current);
        current = current->link;
    }
}


// 사전을 화면에 출력 ("단어\t빈도" 형식)
/*
리스트를 순회하면서 단어와 빈도를 출력
리스트 순회하기 위해서 임시 노드 포인터인 current 선언
*/
void print_dic( LIST *pList)
{
	NODE *current = pList->head;

	while (current != NULL)
	{
		printf("%s\t%d\n", current->dataPtr->word, current->dataPtr->freq);
		current = current->link;
	}
}

void print_dic_by_freq( LIST *pList)
{
	NODE *current = pList->head2;

	while (current != NULL)
	{
		printf("%s\t%d\n", current->dataPtr->word, current->dataPtr->freq);
		current = current->link2;
	}
}

/*
update_dic에서 전달받은 word에 대해 tWord 구조체를 선언 및 만들어서 구조체의 주소를 반환.
*/
tWord *createWord(char *word) {
    tWord *inputWord = (tWord *)malloc(sizeof(tWord));
    if (inputWord == NULL) {
        printf("Memory allocation failed for tWord structure!\n");
        return NULL; 
    }

    inputWord->word = strdup(word);
    if (inputWord->word == NULL) {
        printf("Memory allocation failed for word string!\n");
        free(inputWord);
        return NULL;
    }

    inputWord->freq = 1;
    return inputWord;
}


//  단어 구조체에 할당된 메모리를 해제
// for destroyList function
void destroyWord( tWord *pNode)
{
	if (pNode) {
		free(pNode->word);
		free(pNode);
	}
}