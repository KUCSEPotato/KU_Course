#define BALANCING

#include <stdlib.h> // malloc
#include <stdio.h>

#include "avlt.h"

#define max(x, y)	(((x) > (y)) ? (x) : (y))


// internal function
// return	height of the (sub)tree from the node (root)
static int getHeight( NODE *root) {
    if (!root) return 0;

    if (root->left) {
        if (root->right) {
            return max(root->left->height, root->right->height) + 1;
        }
        else {
            return root->left->height + 1;
        }
    }
    else {
        if (root->right) {
            return root->right->height + 1;
        }
        else {
            return 1;
        }
    }
}

// internal function
// Exchanges pointers to rotate the tree to the right
// updates heights of the nodes
// return new root
// rotate 될 루트 노드가 인자로 전달됨.
// 손코딩 후보
static NODE *rotateRight(NODE *root) {
    NODE *newRoot = root->left;
    
    root->left = newRoot->right;
    newRoot->right = root;

    // Update heights
    root->height = getHeight(root);
    newRoot->height = getHeight(newRoot);

    return newRoot;
}

// internal function
// Exchanges pointers to rotate the tree to the left
// updates heights of the nodes
// return new root
// rotate 될 루트 노드가 인자로 전달됨.
// 손코딩 후보
static NODE *rotateLeft(NODE *root) {
    NODE *newRoot = root->right;
    
    root->right = newRoot->left;
    newRoot->left = root;

    // Update heights
    root->height = getHeight(root);
    newRoot->height = getHeight(newRoot);

    return newRoot;
}


// internal functions (not mandatory)
// used in AVLT_Insert
// return pointer to root
static NODE *_insert(NODE *root, NODE *newPtr, int (*compare)(const void *, const void *), void (*callback)(void *), int *duplicated) {
    if (root == NULL) { // 1.이미 존재하는 값의 경우
        *duplicated = 0;
        root = newPtr;
    }
    // 2. 삽입이 필요한 경우
    int cmp = compare(newPtr->dataPtr, root->dataPtr);
    if (cmp < 0) { // 1. newPtr이 root 보다 앞서는 경우
        if (root->left) root->left = _insert(root->left, newPtr, compare, callback, duplicated);
        else root->left = newPtr;
    }
    else if (cmp > 0) { // 2. newPtr이 root 보다 뒤에 있는 경우
        if (root->right) root->right = _insert(root->right, newPtr, compare, callback, duplicated);
        else root->right = newPtr;
    }
    else { // 3. newPtr == root
        *duplicated = 1;
        callback(root->dataPtr);
    }

// Balance 요소 계산
    int Balance = getHeight(root->left) - getHeight(root->right);

    if (Balance > 1) {
        int LBalance = getHeight(root->left->left) - getHeight(root->left->right);
        if (LBalance >= 0) { // LL
            root = rotateRight(root);
        }
        else { // LR
            root->left = rotateLeft(root->left);
            root = rotateRight(root);
        }
    }
    else if (Balance < -1) {
        int RBalance = getHeight(root->right->right) - getHeight(root->right->left);
        if (RBalance >= 0) { // RR
            root = rotateLeft(root);
        }
        else { // RL
            root->right = rotateRight(root->right);
            root = rotateLeft(root);
        }
    }

    root->height = getHeight(root);
    return root; // Return the (unchanged) root pointer
}

// used in AVLT_Insert
static NODE *_makeNode( void *dataInPtr) {
    NODE *NewNode = (NODE *)malloc(sizeof(NODE));

    NewNode->dataPtr = dataInPtr;
    NewNode->left = NULL;
    NewNode->right = NULL;
    NewNode->height = 1;

    return NewNode;
}

// used in AVLT_Destroy
// callback 함수는 destroyWord
static void _destroy( NODE *root, void (*callback)(void *)) {
    if (root->left) {
        _destroy(root->left, callback);
    }
    if (root->right) {
        _destroy(root->right, callback);
    }
    callback(root->dataPtr);
    free(root);
}

// used in AVLT_Delete
// return 	pointer to root
static NODE *_delete( NODE *root, void *keyPtr, void **dataOutPtr, int (*compare)(const void *, const void *)) {
    if (root == NULL) return NULL;

    int cmp = compare(keyPtr, root->dataPtr);
    if (cmp < 0) { // key값이 root보다 앞서는 경우
        root->left = _delete(root->left, keyPtr, dataOutPtr, compare);
    }
    else if (cmp > 0) { // key값이 root보다 뒤인 경우 
        root->right = _delete(root->right, keyPtr, dataOutPtr, compare);
    }
    else { // key == root인 경우
        *dataOutPtr = root->dataPtr;

        if (root->left == NULL && root->right == NULL) { // 1. 자식이 없는 경우
            free(root);
            return NULL;
        }
        else if (root->left == NULL) { // 2. 오른쪽 서브트리만 있는 경우
            NODE *temp = root->right;
            free(root);
            return temp;
        }
        else if (root->right == NULL) { // 3. 왼쪽 서브트리만 있는 경우
            NODE *temp = root->left;
            free(root);
            return temp;
        }
        else { // 4. 자식(서브트리)이(가) 둘 인 경우
            NODE *temp = root->right;
            NODE *parent = root;

            // 1. root의 오른쪽 서브트리에서 가장 왼쪽 노드를 찾는다.
            while (temp->left != NULL) {
                parent = temp;
                temp = temp->left;
            }
            // 2. root에 데이터 복사
            root->dataPtr = temp->dataPtr;
            // 3. 2에서 복사한 NODE 삭제
            if (parent->left == temp) {
                parent->left = temp->right;
            } 
            else {
                parent->right = temp->right;
            }
            free(temp);   
            //free(parent);
        }
    }
    return root;
}

// used in AVLT_Search
// Retrieve node containing the requested key
// return	address of the node containing the key
//			NULL not found
static NODE *_search( NODE *root, void *keyPtr, int (*compare)(const void *, const void *)) {
    int found = 0;
    int cmp = compare(root->dataPtr, keyPtr);
    
    if (cmp < 0) { // root가 키보다 사전적으로 앞서는 경우
        _search(root->left, keyPtr, compare);
    }
    else if (cmp > 0) { // root가 키보다 사전적으로 뒤에오는 경우
        _search(root->right, keyPtr, compare);
    }
    else { // key값을 찾은 경우
        found = 1;
    }
    
    if (found == 1) {
        return root;
    }
    else {
        return NULL;
    }
    
}

// used in AVLT_Traverse
static void _traverse( NODE *root, void (*callback)(const void *)) {
    if (root->left) {
        _traverse(root->left, callback);
    }
    
    callback(root->dataPtr);
    
    if (root->right) {
        _traverse(root->right, callback);
    }
}

// used in AVLT_TraverseR
static void _traverseR( NODE *root, void (*callback)(const void *)) {
    if (root->right) {
        _traverseR(root->right, callback);
    }
    
    callback(root->dataPtr);

    if (root->left) {
        _traverseR(root->left, callback);
    }
}

// used in printTree
static void _inorder_print( NODE *root, int level, void (*callback)(const void *)) {
    if (root == NULL) {
        return;
    }

    // Traverse right subtree first for right-to-left inorder
    _inorder_print(root->right, level + 1, callback);

    // Print current node at its level
    for (int i = 0; i < level; i++) {
        printf("\t");  // Use tabs to denote levels of depth
    }
    callback(root->dataPtr);

    // Traverse left subtree
    _inorder_print(root->left, level + 1, callback);
}


////////////////////////////////////////////////////////////////////////////////
// Prototype declarations

/* Allocates dynamic memory for a tree head node and returns its address to caller
	return	head node pointer
			NULL if overflow
*/
TREE *AVLT_Create( int (*compare)(const void *, const void *)) {
    TREE *AVL_Tree = (TREE *)malloc(sizeof(TREE));
    if (AVL_Tree == NULL) return NULL;

    AVL_Tree->count = 0;
    AVL_Tree->root = NULL;
    AVL_Tree->compare = compare;

    return AVL_Tree; 
}

/* Deletes all data in tree and recycles memory
*/
void AVLT_Destroy( TREE *pTree, void (*callback)(void *)) {
    if (pTree->root) { // 트리가 비어 있지 않은 경우에만 _destroy 호출
        _destroy(pTree->root, callback);
    }
    free(pTree);
}

/* Inserts new data into the tree
	callback은 이미 트리에 존재하는 데이터를 발견했을 때 호출하는 함수
	return	1 success
			0 overflow
			2 if duplicated key
*/
int AVLT_Insert( TREE *pTree, void *dataInPtr, void (*callback)(void *)) {
    int duplicated = 0;

    NODE *NewNode = _makeNode(dataInPtr);
    if (!NewNode) return 0;

    if (pTree->root == NULL) {
        pTree->root = NewNode;
        pTree->count++;
        return 1;
    }
    else {
        pTree->root = _insert(pTree->root, NewNode, pTree->compare, callback, &duplicated);

        if (duplicated) {
            free(NewNode);
            return 2;
        } 
        else {
            pTree->count++;
            return 1;
        }
    }
}

/* Deletes a node with keyPtr from the tree
	return	address of data of the node containing the key
			NULL not found
*/
void *AVLT_Delete( TREE *pTree, void *keyPtr) {
    void *dataOutPtr = NULL;

    pTree->root = _delete(pTree->root, keyPtr, &dataOutPtr, pTree->compare);
    if (dataOutPtr != NULL) {
        pTree->count--;
    }

    return dataOutPtr;
}

/* Retrieve tree for the node containing the requested key (keyPtr)
	return	address of data of the node containing the key
			NULL not found
*/
void *AVLT_Search( TREE *pTree, void *keyPtr) {
    if (pTree->count == 0) return NULL;

    NODE *foundNode = _search(pTree->root, keyPtr, pTree->compare);
    if (!foundNode) return NULL;

    return foundNode->dataPtr;
}

/* prints tree using inorder traversal
*/
void AVLT_Traverse( TREE *pTree, void (*callback)(const void *)) {
    if (pTree->root) {
        _traverse(pTree->root, callback);
    }
}

/* prints tree using right-to-left inorder traversal
*/
void AVLT_TraverseR( TREE *pTree, void (*callback)(const void *)) {
    if (pTree->root) {
        _traverseR(pTree->root, callback);
    }
}

/* Print tree using right-to-left inorder traversal with level
*/
void printTree( TREE *pTree, void (*callback)(const void *)) {
    if (!(pTree->root)) {
        printf("Tree is empty!");
        return ;
    }
    else {
        _inorder_print(pTree->root, 0, callback);
    }
}

/* returns number of nodes in tree
*/
int AVLT_Count( TREE *pTree) {
    return pTree->count;
}

/* returns height of the tree
*/
int AVLT_Height( TREE *pTree) {
    if (pTree->root) return pTree->root->height;
    else return 0;
}
