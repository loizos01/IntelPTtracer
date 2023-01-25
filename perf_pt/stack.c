struct node{
    char buffer[50];
    uint64_t ip;
    struct node *next;
};

struct node *head= NULL;


void push (uint64_t ip, char* buffer){
    struct node *ptr = (struct node*)malloc(sizeof(struct node));

    if(head == NULL){
        ptr->ip = ip;
        memcpy( ptr->buffer, buffer, 50); 
        ptr->next = NULL;
        head = ptr;
    }
    else{
        ptr->ip = ip;
        memcpy( ptr->buffer, buffer, 50); 
        ptr->next = head;
        head=ptr;
    }
}

node *head pop(){
    if (head == NULL)
        return NULL;
    else{
        item = head->val;
        ptr = head;
        head = head->next;
        free(ptr);
        printf("%d is popped out of the stack", item);
        return item;
    }
    return -1;
}

bool isEmpty(){
    if(head == NULL){
        printf("Stack is empty: Underflow State\n");
        return true;
    }
    printf("Stack is not empty\n");
    return false;
}
