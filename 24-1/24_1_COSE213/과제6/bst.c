#include <stdlib.h> // malloc
#include <stdio.h>

#include "bst.h"

////////////////////////////////////////////////////////////////////////////////
// Prototype declarations

/* Allocates dynamic memory for a tree head node and returns its address to caller
	return	head node pointer
			NULL if overflow
*/
TREE *BST_Create( int (*compare)(const void *, const void *)) {
    TREE *HeadTree = (TREE *)malloc(sizeof(TREE));
    if (HeadTree == NULL) exit(1);

    HeadTree->count = 0;
    HeadTree->root = NULL;
    HeadTree->compare = compare;

    return HeadTree;
}

// used in BST_Destroy
static void _destroy( NODE *root, void (*callback)(void *)) {
    if (root->left != NULL) {
        _destroy(root->left, callback);
    }
    if (root->right != NULL) {
        _destroy(root->right, callback);
    }
    callback(root->dataPtr);
    free(root);
}

/* Deletes all data in tree and recycles memory
*/
void BST_Destroy( TREE *pTree, void (*callback)(void *)) {
if (pTree->root != NULL) {
        _destroy(pTree->root, callback);
    }
    free(pTree);
}

// internal functions (not mandatory)
// used in BST_Insert
// 삽입 성공 1, 실패 0
static int _insert( NODE *root, NODE *newPtr, int (*compare)(const void *, const void *), void (*callback)(void *)) {
    if (root == NULL) {
        return 0;
    }

    if (compare(newPtr->dataPtr, root->dataPtr) < 0) { // newPtr이 root보다 작은 경우
        if (root->left == NULL) {
            root->left = newPtr;
            return 1;
        }
        else {
            return _insert(root->left, newPtr, compare, callback);
        }
    } 
    else if (compare(newPtr->dataPtr, root->dataPtr) > 0) { // newPtr이 root보다 큰 경우
        if (root->right == NULL) {
            root->right = newPtr;
            return 1;
        } 
        else {
            return _insert(root->right, newPtr, compare, callback);
        }
    } else {
        // 이미 존재하는 경우
        return 0;
    }
}
// used in BST_Insert
static NODE *_makeNode( void *dataInPtr) {
    NODE *NewNode = (NODE *)malloc(sizeof(NODE));
    if (NewNode == NULL) {
        printf("Memory allocation for Node failed!");
        return NULL;
    }

    NewNode->dataPtr = dataInPtr;
    NewNode->left = NULL;
    NewNode->right = NULL;

    return NewNode;
}

/* Inserts new data into the tree
	callback은 이미 트리에 존재하는 데이터를 발견했을 때 호출하는 함수
	return	0 overflow
			1 success
			2 if duplicated key
*/
int BST_Insert( TREE *pTree, void *dataInPtr, void (*callback)(void *)) {
    void *found = BST_Search(pTree, dataInPtr);

    if (found) { // 삽입하려는 값이 이미 TREE에 있는 경우
        callback(found);
        return 2;
    } 
    else { // 삽입하려는 값이 TREE에 없는 경우
        NODE *newNode = _makeNode(dataInPtr);
        if (newNode == NULL) return 0;

        if (pTree->root == NULL) {
            pTree->root = newNode;
        } 
        else {
            if (!_insert(pTree->root, newNode, pTree->compare, callback)) {
                free(newNode);
                return 0;
            }
        }
        pTree->count++;
        return 1;
    }
}


// used in BST_Delete
// return 	pointer to root
static NODE *_delete( NODE *root, void *keyPtr, void **dataOutPtr, int (*compare)(const void *, const void *)) {
    if (root == NULL) return NULL;

    int cmpres = compare(keyPtr, root->dataPtr);
    if (cmpres < 0) {
        root->left = _delete(root->left, keyPtr, dataOutPtr, compare);
    } 
    else if (cmpres > 0) {
        root->right = _delete(root->right, keyPtr, dataOutPtr, compare);
    } 
    else {
        *dataOutPtr = root->dataPtr;
        // 1. 자식이 없을 경우
        if (root->left == NULL && root->right == NULL) {
            free(root);
            return NULL;
        }
        // 2. 자식이 하나인 경우 (왼쪽)
        else if (root->right == NULL) { 
            NODE *temp = root->left;
            free(root);
            return temp;
        }
        // 3. 자식이 하나인 경우 (오른쪽)
        else if (root->left == NULL) {
            NODE *temp = root->right;
            free(root);
            return temp;
        }
        // 4. 자식이 둘인 경우
        else {
            NODE *temp = root->right;
            NODE *parent = root;

            // 가장 왼쪽 노드를 찾습니다.
            while (temp->left != NULL) {
                parent = temp;
                temp = temp->left;
            }

            // 데이터를 복사합니다.
            root->dataPtr = temp->dataPtr;

            // 가장 왼쪽 노드를 삭제합니다.
            if (parent->left == temp) {
                parent->left = temp->right;
            } 
            else {
                parent->right = temp->right;
            }
            
            free(temp);
        }
    }
    return root;
}

/* Deletes a node with keyPtr from the tree
	return	address of data of the node containing the key
			NULL not found
*/
void *BST_Delete( TREE *pTree, void *keyPtr) {
    void *dataOutPtr = NULL;

    pTree->root = _delete(pTree->root, keyPtr, &dataOutPtr, pTree->compare);
    if (dataOutPtr != NULL) {
        pTree->count--;
    }

    return dataOutPtr;
}

// used in BST_Search
// Retrieve node containing the requested key
// return	address of the node containing the key
//			NULL not found
// compares two words in word structures
// for BST_Create function
// 정렬 기준 : 단어
static NODE *_search( NODE *root, void *keyPtr, int (*compare)(const void *, const void *)) {
    if (root == NULL) return NULL;

    int cmpres = compare(keyPtr, root->dataPtr);
    if (cmpres < 0) return _search(root->left, keyPtr, compare);
    else if (cmpres > 0) return _search(root->right, keyPtr, compare);
    else return root;
}

/* Retrieve tree for the node containing the requested key (keyPtr)
	return	address of data of the node containing the key
			NULL not found
*/
void *BST_Search(TREE *pTree, void *keyPtr) {
    if (pTree->count == 0) return NULL;
    
    NODE *foundNode = _search(pTree->root, keyPtr, pTree->compare);
    
    if (!foundNode) return NULL;
    else return foundNode->dataPtr;
}

// used in BST_Traverse
static void _traverse(NODE *root, void (*callback)(const void *)) {
    if (root->left) {
        _traverse(root->left, callback);
    }
    callback(root->dataPtr);

    if (root->right) {
        _traverse(root->right, callback);
    }
}

/* prints tree using inorder traversal
*/
void BST_Traverse( TREE *pTree, void (*callback)(const void *)) {
    if (pTree->root != NULL) {
        _traverse(pTree->root, callback);
    }
}

// used in BST_TraverseR
static void _traverseR( NODE *root, void (*callback)(const void *)) {
    if (root->right) {
        _traverseR(root->right, callback);
    }
    callback(root->dataPtr);

    if (root->left) {
        _traverseR(root->left, callback);
    }
}

/* prints tree using right-to-left inorder traversal
*/
void BST_TraverseR( TREE *pTree, void (*callback)(const void *)) {
    if (pTree->root != NULL) {
        _traverseR(pTree->root, callback);
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

//Print tree using right-to-left inorder traversal with level
void printTree( TREE *pTree, void (*callback)(const void *)) {
    if (pTree->root == NULL) {
        printf("Tree is empty!\n");
        return;  // Just return after notifying that the tree is empty
    } else {
        _inorder_print(pTree->root, 0, callback);
    }
}

/* returns number of nodes in tree
*/
int BST_Count( TREE *pTree) {
    return pTree->count;
}



