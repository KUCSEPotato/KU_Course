#include <stdio.h>
#include <stdlib.h> // malloc
#include <string.h> // strdup, strcmp
#include <ctype.h> // toupper

#define QUIT			1
#define FORWARD_PRINT	2
#define BACKWARD_PRINT	3
#define SEARCH			4
#define DELETE			5
#define COUNT			6

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
	struct node	*llink; // backward pointer
	struct node	*rlink; // forward pointer
} NODE;

typedef struct
{
	int		count;
	NODE	*head;
	NODE	*rear;
} LIST;

////////////////////////////////////////////////////////////////////////////////
// Prototype declarations

// Allocates dynamic memory for a list head node and returns its address to caller
// return	head node pointer
// 			NULL if overflow
LIST *createList(void);

//  단어 리스트에 할당된 메모리를 해제 (head node, data node, word data)
void destroyList( LIST *pList);

// Inserts data into list
// return	0 if overflow
//			1 if successful
//			2 if duplicated key (이미 저장된 단어는 빈도 증가)
int addNode( LIST *pList, tWord *dataInPtr);

// Removes data from list
//	return	0 not found
//			1 deleted
int removeNode( LIST *pList, tWord *keyPtr, tWord **dataOutPtr);

// interface to search function
//	pArgu	key being sought
//	dataOutPtr	contains found data
//	return	1 successful
//			0 not found
int searchNode( LIST *pList, tWord *pArgu, tWord **dataOutPtr);

// returns number of nodes in list
int countList( LIST *pList);

// returns	1 empty
//			0 list has data
int emptyList( LIST *pList);

// traverses data from list (forward)
void traverseList( LIST *pList, void (*callback)(const tWord *));

// traverses data from list (backward)
void traverseListR( LIST *pList, void (*callback)(const tWord *));

// internal insert function
// inserts data into list
// for addNode function
// return	1 if successful
// 			0 if memory overflow
static int _insert( LIST *pList, NODE *pPre, tWord *dataInPtr);

// internal delete function
// deletes data from list and saves the (deleted) data to dataOutPtr
// for removeNode function
static void _delete( LIST *pList, NODE *pPre, NODE *pLoc, tWord **dataOutPtr);

// internal search function
// searches list and passes back address of node containing target and its logical predecessor
// for addNode, removeNode, searchNode functions
// return	1 found
// 			0 not found
static int _search( LIST *pList, NODE **pPre, NODE **pLoc, tWord *pArgu);

////////////////////////////////////////////////////////////////////////////////
// 단어 구조체를 위한 메모리를 할당하고 word, freq 초기화// return	word structure pointer
// return	할당된 단어 구조체에 대한 pointer
//			NULL if overflow
tWord *createWord( char *word);

//  단어 구조체에 할당된 메모리를 해제
// for destroyList function
void destroyWord( tWord *pNode);

////////////////////////////////////////////////////////////////////////////////
// gets user's input
int get_action()
{
	char ch;
	scanf( "%c", &ch);
	ch = toupper( ch);
	switch( ch)
	{
		case 'Q':
			return QUIT;
		case 'P':
			return FORWARD_PRINT;
		case 'B':
			return BACKWARD_PRINT;
		case 'S':
			return SEARCH;
		case 'D':
			return DELETE;
		case 'C':
			return COUNT;
	}
	return 0; // undefined action
}

// compares two words in word structures
// for _search function
// 정렬 기준 : 단어
int compare_by_word( const void *n1, const void *n2)
{
	tWord *p1 = (tWord *)n1;
	tWord *p2 = (tWord *)n2;
	
	return strcmp( p1->word, p2->word);
}

// prints contents of name structure
// for traverseList and traverseListR functions
void print_word(const tWord *dataPtr)
{
	printf( "%s\t%d\n", dataPtr->word, dataPtr->freq);
}

// gets user's input
void input_word(char *word)
{
	fprintf( stderr, "Input a word to find: ");
	fscanf( stdin, "%s", word);
}

////////////////////////////////////////////////////////////////////////////////
int main( int argc, char **argv)
{
	LIST *list;
	
	char word[100];
	tWord *pWord;
	int ret;
	FILE *fp;
	
	if (argc != 2){
		fprintf( stderr, "usage: %s FILE\n", argv[0]);
		return 1;
	}
	
	fp = fopen( argv[1], "rt");
	if (!fp)
	{
		fprintf( stderr, "Error: cannot open file [%s]\n", argv[1]);
		return 2;
	}
	
	// creates an empty list
	list = createList();
	if (!list)
	{
		printf( "Cannot create list\n");
		return 100;
	}
	
	while(fscanf( fp, "%s", word) != EOF)
	{
		pWord = createWord( word);
		
		// 이미 저장된 단어는 빈도 증가
		ret = addNode( list, pWord);
		
		if (ret == 0 || ret == 2) // failure or duplicated
		{
			destroyWord( pWord);
		}
	}
	
	fclose( fp);
	
	fprintf( stderr, "Select Q)uit, P)rint, B)ackward print, S)earch, D)elete, C)ount: ");
	
	while (1)
	{
		tWord *ptr;
		int action = get_action();
		
		switch( action)
		{
			case QUIT:
				destroyList( list);
				return 0;
			
			case FORWARD_PRINT:
				traverseList( list, print_word);
				break;
			
			case BACKWARD_PRINT:
				traverseListR( list, print_word);
				break;
			
			case SEARCH:
				input_word(word);
				
				pWord = createWord( word);

				if (searchNode( list, pWord, &ptr)) print_word( ptr);
				else fprintf( stdout, "%s not found\n", word);
				
				destroyWord( pWord);
				break;
				
			case DELETE:
				input_word(word);
				
				pWord = createWord( word);

				if (removeNode( list, pWord, &ptr))
				{
					fprintf( stdout, "(%s, %d) deleted\n", ptr->word, ptr->freq);
					destroyWord( ptr);
				}
				else fprintf( stdout, "%s not found\n", word);
				
				destroyWord( pWord);
				break;
			
			case COUNT:
				fprintf( stdout, "%d\n", countList( list));
				break;
		}
		
		if (action) fprintf( stderr, "Select Q)uit, P)rint, B)ackward print, S)earch, D)elete, C)ount: ");
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
// Prototype declarations

// Allocates dynamic memory for a list head node and returns its address to caller
// return	head node pointer
// 			NULL if overflow
LIST *createList(void)
{
	LIST *HeadNode = (LIST *)malloc(sizeof(LIST));
	if (HeadNode == NULL){
		printf("Memory allocation failled!");
		exit(1);
	}

	HeadNode->count = 0;
	HeadNode->head = NULL;
	HeadNode->rear = NULL;

	return HeadNode;
}

//  단어 리스트에 할당된 메모리를 해제 (head node, data node, word data)
void destroyList( LIST *pList)
{
	if (pList == NULL) return;
	NODE *temp = pList->head;
	NODE *next = NULL;

	while (temp != NULL)
	{
		next = temp->rlink;
		destroyWord(temp->dataPtr);
		free(temp);
		temp = next;
	}
	free(pList);	
}

// Inserts data into list
// return	0 if overflow
//			1 if successful
//			2 if duplicated key (이미 저장된 단어는 빈도 증가)
int addNode(LIST *pList, tWord *dataInPtr) {
    NODE *pPre = NULL;
    NODE *pLoc = NULL;
    
    // 먼저 리스트에서 해당 데이터가 존재하는지 검색
    int found = _search(pList, &pPre, &pLoc, dataInPtr);
    
    if (found) 
	{
        pLoc->dataPtr->freq += 1;  // 단어 빈도수 증가
        return 2;                  // 중복된 키 처리
    } 
	else 
	{
        // 새 노드 생성
        NODE *pNew = (NODE *)malloc(sizeof(NODE));
        if (pNew == NULL) {
            printf("Memory allocation failed!");
            return 0;
        }
        pNew->dataPtr = dataInPtr;
        
        // 새 노드 삽입
        if (!_insert(pList, pPre, pNew->dataPtr)) {
			free(pNew);
            printf("Insertion Failed!");
            exit(1);
        }
        
        return 1;  // 삽입 성공
    }
}


// Removes data from list
//	return	0 not found
//			1 deleted
int removeNode( LIST *pList, tWord *keyPtr, tWord **dataOutPtr)
{
	NODE *pPre = NULL;
	NODE *pLoc = pList->head;

	if (!_search(pList, &pPre, &pLoc, keyPtr))
	{
		return 0;
	}
	else 
	{
		_delete(pList, pPre, pLoc, dataOutPtr);	
		return 1;
	}
}

// interface to search function
//	pArgu	key being sought
//	dataOutPtr	contains found data
//	return	1 successful
//			0 not found
int searchNode( LIST *pList, tWord *pArgu, tWord **dataOutPtr)
{
	NODE *pPre = NULL;
	NODE *pLoc = pList->head;
	int found = _search(pList, &pPre, &pLoc, pArgu);
	
	if (found)
	{
		*dataOutPtr = pLoc->dataPtr;
		return 1;
	}
	else
	{
		return 0;
	}
}

// returns number of nodes in list
int countList( LIST *pList)
{
	return (pList->count);
}

// returns	1 empty
//			0 list has data
// int emptyList( LIST *pList);

// traverses data from list (forward)
void traverseList( LIST *pList, void (*callback)(const tWord *))
{
	NODE *temp = pList->head;
	NODE *next = NULL;

	while (temp != NULL) {
	next = temp->rlink;
    callback(temp->dataPtr);
    temp = next; // Move to next node in the list
	}
}

// traverses data from list (backward)
void traverseListR( LIST *pList, void (*callback)(const tWord *))
{
	NODE *temp = pList->rear;
	NODE *next = NULL;

	while (temp != NULL) {
	next = temp ->llink;
    callback(temp->dataPtr);
    temp = next;// Move to next node in the list
	}
}

// internal insert function
// inserts data into list
// for addNode function
// return	1 if successful
// 			0 if memory overflow
static int _insert( LIST *pList, NODE *pPre, tWord *dataInPtr)
{
	NODE *newword = (NODE *)malloc(sizeof(NODE));
	if (newword == NULL)
	{
		printf("Memory allocation failed!");
		return 0;
	}

	newword->dataPtr = dataInPtr;
	newword->llink = NULL;
	newword->rlink = NULL;

	if (pList->head == NULL) { // 빈 리스트에 삽입하는 경우
		pList->head = newword;
		pList->rear = newword;
	}
	else if (pPre == NULL) { // 맨 앞에 삽입
		newword->rlink = pList->head;
		pList->head->llink = newword;
		pList->head = newword;
	}
	else { //중간 또는 끝에 삽입
		if (pPre->rlink == NULL) { // 끝
			pPre->rlink = newword;
			newword->llink = pPre;
			newword->rlink = NULL;
			pList->rear = newword;
		}
		else { // 중간
			newword->rlink = pPre->rlink;
			pPre->rlink->llink = newword;
			pPre->rlink = newword;
			newword->llink = pPre;
		}
	}

	pList->count += 1;
	return 1;
}

// internal delete function
// deletes data from list and saves the (deleted) data to dataOutPtr
// for removeNode function
static void _delete(LIST *pList, NODE *pPre, NODE *pLoc, tWord **dataOutPtr) 
{
    NODE *temp = pLoc;
    
	if (pLoc->llink == NULL) { // 첫 번째 요소인 경우
        pList->head = pLoc->rlink;
        if (pList->head != NULL) { // 요소 삭제 후의 리스트가 빈 리스트가 아닌 경우
            pList->head->llink = NULL;
        }
    } 
	else if (pLoc->rlink == NULL) { // 마지막 요소인 경우
        pPre->rlink = NULL;
        pList->rear = pPre;
    } 
	else { // 중간 요소인 경우
        pPre->rlink = pLoc->rlink;
        pLoc->rlink->llink = pPre;
    }

    *dataOutPtr = temp->dataPtr;
    pList->count--;
	free(temp);
}


// internal search function
// searches list and passes back address of node containing target and its logical predecessor
// for addNode, removeNode, searchNode functions
// return	1 found
// 			0 not found
static int _search( LIST *pList, NODE **pPre, NODE **pLoc, tWord *pArgu)
{
	*pPre = NULL;
	*pLoc = pList->head;

	while (*pLoc != NULL && compare_by_word(pArgu, (*pLoc)->dataPtr) > 0)
	{
		*pPre = *pLoc;
		*pLoc = (*pLoc)->rlink;
	}

	if (*pLoc != NULL && compare_by_word(pArgu, (*pLoc)->dataPtr) == 0)
	{
		return 1;
	}
	else 
	{
		return 0;
	}
}

////////////////////////////////////////////////////////////////////////////////
// 단어 구조체를 위한 메모리를 할당하고 word, freq 초기화// return	word structure pointer
// return	할당된 단어 구조체에 대한 pointer
//			NULL if overflow
tWord *createWord(char *word) {
    tWord *Newword = (tWord *)malloc(sizeof(tWord));
    if (Newword == NULL) {
        printf("Memory allocation failed!");
        exit(1);
    }

    Newword->word = strdup(word);  // 문자열 복사
    if (Newword->word == NULL) {
        free(Newword);  // strdup 실패 시 Newword 해제
        return NULL;
    }

    Newword->freq = 1;
    return Newword;
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