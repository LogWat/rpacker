#include <windows.h>
#include <winnt.h>

#define MAX_STACK_SIZE 256 // 0x00 ~ 0xFF
#define ALPHABET_SIZE 256

void memcpys(char* dst, char* src, unsigned int size) {
    for (int i = 0; i < size; i++) dst[i] = src[i];
}

// 1bitを配列の1要素として扱う
void bitmemcpy(char *dst, char *src, unsigned int size, unsigned int bit_pos) {
    unsigned int count = bit_pos;
    for (int i = 0; i < size; i++) {
        char bit = (src[count / 8] >> (7 - (count % 8))) & 1;
        dst[i] = bit;
        count++;
    }
}

unsigned int u8_to_u32(unsigned char* data) {
    return (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
}

char bits_to_char(char* bits) {
    char c = 0;
    for (int i = 0; i < 8; i++) {
        c |= bits[i] << (7 - i);
    }
    return c;
}

/* Huffman Encoding ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
/* reference: https://zenn.dev/k_kuroguro/articles/f7a63cd08447b6 */

typedef struct Code {
    unsigned int compressed_char_count;
    unsigned int original_char_count;
    unsigned int tree_topology_size;
    char* tree_topology; // bit列
    char* compressed_data; // bit列
} Code_t;

// ==================================================

typedef struct Node {
    struct Node* left;
    struct Node* right;
    char c;
} Node_t;

Node_t* new_node(Node_t* left, Node_t* right, char c) {
    Node_t* node = (Node_t*) VirtualAlloc(NULL, sizeof(Node_t), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    node->left = left;
    node->right = right;
    node->c = c;
    return node;
}

// Vec型============================================
typedef struct Vec {
    char* data;
    unsigned int size;
    unsigned int capacity;
} Vec_t;

void vec_free(Vec_t* vec) {
    VirtualFree(vec->data, 0, MEM_RELEASE);
    VirtualFree(vec, 0, MEM_RELEASE);
}

// 256SizeのVecを作成
Vec_t* vec_new() {
    Vec_t* vec = (Vec_t*) VirtualAlloc(NULL, sizeof(Vec_t), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    vec->data = (char*) VirtualAlloc(NULL, ALPHABET_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    vec->size = 0;
    vec->capacity = ALPHABET_SIZE;
    return vec;
}

Vec_t* vec_new_with_capasity(unsigned int capacity) {
    Vec_t* vec = (Vec_t*) VirtualAlloc(NULL, sizeof(Vec_t), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    vec->data = (char*) VirtualAlloc(NULL, capacity, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    vec->size = 0;
    vec->capacity = capacity;
    return vec;
}

void vec_push(Vec_t* vec, char *c) {
    if (vec->size >= vec->capacity) {
        unsigned int new_capacity = vec->capacity * 2;
        Vec_t* new_vec = vec_new_with_capasity(new_capacity);
        memcpys(new_vec->data, vec->data, vec->size);
        new_vec->size = vec->size;
        vec_free(vec);
        vec = new_vec;
    }
    vec->data[vec->size] = *c;
    vec->size++;
}

char vec_pop(Vec_t* vec) {
    if (vec->size == 0) {
        return 0;
    }
    char c = vec->data[vec->size - 1];
    vec->size--;
    return c;
}

int vec_cmp(Vec_t* vec1, Vec_t* vec2) {
    if (vec1->size != vec2->size) {
        return 0;
    }
    for (int i = 0; i < vec1->size; i++) {
        if (vec1->data[i] != vec2->data[i]) {
            return 0;
        }
    }
    return 1;
}

int vec_cmp_reverse(Vec_t* vec1, Vec_t* vec2) {
    if (vec1->size != vec2->size) {
        return 0;
    }
    unsigned int size = vec1->size;
    for (int i = 0; i < vec1->size; i++) {
        if (vec1->data[size - i - 1] != vec2->data[i]) {
            return 0;
        }
    }
    return 1;
}
// ================================================

typedef struct BitsCharMap {
    Vec_t bits[ALPHABET_SIZE]; // 256個のVec
} BitsCharMap_t;

BitsCharMap_t* new_bits_char_map() {
    BitsCharMap_t* map = (BitsCharMap_t*) VirtualAlloc(NULL, sizeof(BitsCharMap_t), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    for (int i = 0; i < 256; i++) {
        map->bits[i] = *vec_new();
    }
    return map;
}

int bitvec_to_char(BitsCharMap_t* map, Vec_t* bits){
    for (int i = 0; i < 256; i++) {
        if (vec_cmp_reverse(&(map->bits[i]), bits)) {
            return i;
        }
    }
    return -1;
}

// Stack型==========================================
typedef struct stack {
    Node_t data[MAX_STACK_SIZE];
    int top;
} Stack_t;

void init_stack(Stack_t* stack) {
    stack->top = 0;
    for (int i = 0; i < MAX_STACK_SIZE; i++) {
        stack->data[i].left = NULL;
        stack->data[i].right = NULL;
        stack->data[i].c = 0;
    }
}

void push(Stack_t* stack, Node_t node) {
    if (stack->top >= MAX_STACK_SIZE) {
        return;
    }
    stack->data[stack->top] = node;
    stack->top++;
}

Node_t pop(Stack_t* stack) {
    if (stack->top <= 0) {
        Node_t node;
        return node;
    }
    stack->top--;
    return stack->data[stack->top];
}
// ================================================

Node_t build_tree(char* tree_topology) {
    Stack_t stack;
    init_stack(&stack);
    unsigned int count = 0;
    while (1) {
        if (tree_topology[count]) {
            count++;
            char c = bits_to_char(&tree_topology[count]);
            count += 8;
            Node_t* node = new_node(NULL, NULL, c);
            push(&stack, *node);
        } else {
            if (stack.top == 1) {
                return pop(&stack);
            }
            count++;
            Node_t* right = new_node(NULL, NULL, 0);
            Node_t* left = new_node(NULL, NULL, 0);
            *right = pop(&stack);
            *left = pop(&stack);
            Node_t* node = new_node(left, right, 0);
            push(&stack, *node);
        }
    }
}

void search_by_dfs_nlr(Node_t* node, BitsCharMap_t* map, Vec_t* vec, int* count) {
    if (node->left == NULL && node->right == NULL) {
        if (vec->size == 0) {
            char c = 0;
            vec_push(vec, &c);
        }
        int index = (unsigned char) node->c;
        unsigned int size = vec->size;
        for (int i = 0; i < size; i++) {
            char c = vec_pop(vec);
            vec_push(&(map->bits[index]), &c);
        }
        (*count)++;
    } else {
        Vec_t* left_vec = vec_new();
        Vec_t* right_vec = vec_new();
        for (int i = 0; i < vec->size; i++) {
            vec_push(left_vec, &(vec->data[i]));
            vec_push(right_vec, &(vec->data[i]));
        }
        char c1 = 0;
        vec_push(left_vec, &c1);
        char c2 = 1;
        vec_push(right_vec, &c2);
        search_by_dfs_nlr(node->left, map, left_vec, count);
        search_by_dfs_nlr(node->right, map, right_vec, count);
    }
}

void build_bits_char_map(Node_t* tree, BitsCharMap_t* map) {
    // 0x00 ~ 0xFF
    Vec_t* bits = vec_new();
    int counter = 0;
    search_by_dfs_nlr(tree, map, bits, &counter);
}

char* decode(char* packed, unsigned int packed_size) {

    Code_t code;
    code.compressed_char_count = u8_to_u32((unsigned char*) packed); // <= 読み取れるサイズはbit数
    code.original_char_count = u8_to_u32((unsigned char*) (packed + 4));
    code.tree_topology_size = u8_to_u32((unsigned char*) (packed + 8)); // <= 読み取れるサイズはbit数
    code.tree_topology = (char*) VirtualAlloc(NULL, code.tree_topology_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    bitmemcpy(code.tree_topology, packed + 12, code.tree_topology_size, 0);
    code.compressed_data = (char*) VirtualAlloc(NULL, code.compressed_char_count, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    unsigned int tree_topology_byte_size = code.tree_topology_size / 8 + (code.tree_topology_size % 8 != 0);
    bitmemcpy(code.compressed_data, packed + 12 + tree_topology_byte_size - (code.tree_topology_size % 8 != 0), code.compressed_char_count, code.tree_topology_size % 8);    

    Node_t tree = build_tree(code.tree_topology);
    BitsCharMap_t* map = new_bits_char_map();
    build_bits_char_map(&tree, map);

    char* unpacked_PE = (char*) VirtualAlloc(NULL, code.original_char_count, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (unpacked_PE == NULL) {
        return NULL;
    }

    Vec_t* bits = vec_new();
    unsigned int unpacked_PE_index = 0;
    for (int i = 0; i < code.compressed_char_count; i++) {
        char c0 = code.compressed_data[i];
        vec_push(bits, &(code.compressed_data[i]));
        int c = bitvec_to_char(map, bits);
        if (c != -1) {
            unpacked_PE[unpacked_PE_index] = c;
            unpacked_PE_index++;
            vec_free(bits);
            bits = vec_new();
        }
    }

    IMAGE_DOS_HEADER* pdosh  = (IMAGE_DOS_HEADER*) unpacked_PE;
    IMAGE_NT_HEADERS* pnth = (IMAGE_NT_HEADERS*) (((char*) pdosh) + pdosh->e_lfanew);
    if (pdosh->e_magic != IMAGE_DOS_SIGNATURE || pnth->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    return unpacked_PE;
}
/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

int resolve_imports(char *PE_data, char* ImageBase) {
    IMAGE_DOS_HEADER* pdosh  = (IMAGE_DOS_HEADER*) PE_data;
    IMAGE_NT_HEADERS* pnth = (IMAGE_NT_HEADERS*) (((char*) pdosh) + pdosh->e_lfanew);
    IMAGE_DATA_DIRECTORY* pdd = pnth->OptionalHeader.DataDirectory;
    IMAGE_IMPORT_DESCRIPTOR* pid = (IMAGE_IMPORT_DESCRIPTOR*) (ImageBase + pdd[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    for (int i = 0; pid[i].Name; i++) {
        HMODULE imd = LoadLibraryA((char*) (pid[i].Name + ImageBase));
        if (imd == NULL) {
            return -1;
        }
        IMAGE_THUNK_DATA* ft = (IMAGE_THUNK_DATA*) (ImageBase + pid[i].FirstThunk);
        IMAGE_THUNK_DATA* oft = (IMAGE_THUNK_DATA*) (ImageBase + pid[i].OriginalFirstThunk);
        for (int j = 0; oft[j].u1.Function; j++) {
            if (oft[j].u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                ft[j].u1.Function = (DWORD) GetProcAddress(imd, (char*) (oft[j].u1.AddressOfData & 0xFFFF));
            } else {
                IMAGE_IMPORT_BY_NAME* pibn = (IMAGE_IMPORT_BY_NAME*) (ImageBase + oft[j].u1.AddressOfData);
                ft[j].u1.Function = (DWORD) GetProcAddress(imd, (char*) pibn->Name);
            }
            if (ft[j].u1.Function == 0) {
                return -1;
            }
        }
    }

    return 0;
}

void* load(char* PE_data) {
    IMAGE_DOS_HEADER* pdosh  = (IMAGE_DOS_HEADER*) PE_data;
    IMAGE_NT_HEADERS* pnth = (IMAGE_NT_HEADERS*) (((char*) pdosh) + pdosh->e_lfanew);

    char *ImageBase = (char *) GetModuleHandleA(NULL);

    DWORD oldp;
    DWORD size_of_headers = pnth->OptionalHeader.SizeOfHeaders;
    VirtualProtect(ImageBase, size_of_headers, PAGE_READWRITE, &oldp);
    memcpys(ImageBase, PE_data, size_of_headers);
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*) (pnth + 1);
    DWORD num_sections = pnth->FileHeader.NumberOfSections;
    for (int i = 0; i < num_sections; i++) {
        char* dest = ImageBase + sections[i].VirtualAddress;
        VirtualProtect(dest, sections[i].Misc.VirtualSize, PAGE_READWRITE, &oldp);
        if (sections[i].SizeOfRawData) {
            memcpys(dest, PE_data + sections[i].PointerToRawData, sections[i].SizeOfRawData);
        }
    }
    VirtualProtect(ImageBase, size_of_headers, PAGE_READONLY, &oldp);

    // IATを使わずLoadLibraryAとGetProcAddressを使って直接関数を呼び出せるようにする
    if (resolve_imports(PE_data, ImageBase) == -1) {
        return NULL;
    }

    // 各セクションの保護属性を設定
    for (int i = 0; i < num_sections; i++) {
        char* dest = ImageBase + sections[i].VirtualAddress;
        DWORD sp = sections[i].Characteristics;
        DWORD vp = 0;
        switch (sp & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)) {
            case IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ:
                vp = PAGE_EXECUTE_READ;
                break;
            case IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE:
                vp = PAGE_EXECUTE_READWRITE;
                break;
            case IMAGE_SCN_MEM_READ:
                vp = PAGE_READONLY;
                break;
            case IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE:
                vp = PAGE_READWRITE;
                break;
            case IMAGE_SCN_MEM_WRITE:
                vp = PAGE_WRITECOPY;
                break;
        }
        VirtualProtect(dest, sections[i].Misc.VirtualSize, vp, &oldp);
    }

    return (void*) (ImageBase + pnth->OptionalHeader.AddressOfEntryPoint);
}

int _start(void) {
    char* peh_addr = (char*) GetModuleHandleA(NULL);

    IMAGE_DOS_HEADER* pdosh  = (IMAGE_DOS_HEADER*) peh_addr;
    IMAGE_NT_HEADERS* pnth = (IMAGE_NT_HEADERS*) (((char*) pdosh) + pdosh->e_lfanew);
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*) (pnth + 1);

    int section_num = pnth->FileHeader.NumberOfSections;
    char* packed = sections[section_num - 1].VirtualAddress + peh_addr;
    packed = decode(packed, sections[section_num - 1].SizeOfRawData);

    if (packed != NULL) {
        void (*original_entry)() = (void(*)()) load(packed);
        original_entry();
    }
}