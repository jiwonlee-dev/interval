#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pbc.h>

#define d_LEVEL 4
#define MSG_SIZE 4096
#define BUF_SIZE 1024

typedef struct param{
	element_t g;
	element_t g1;
	element_t g2;
	element_t g3_left;
	element_t g3_right;
	element_t h_left[d_LEVEL];
	element_t h_right[d_LEVEL];
}param;

typedef struct SK_j{
	element_t a0;
	element_t a1;
	element_t b[d_LEVEL];
}SK_j;

typedef struct DecKey{
	element_t SK_right[2];
	SK_j** SK_right_j;
	element_t SK_left[2];
	SK_j** SK_left_j;

}DecKey;

typedef struct Hdr{
	element_t CT;
	element_t C_left[2];
	element_t C_right[2];
}Hdr;

typedef struct IntervalSet{
	int left;
	int right;
}IntervalSet;

param* init_param(pairing_t pairing){
	int i;
	param* p;
	p = (param*)malloc(sizeof(param));
	element_init_G1(p->g, pairing);
	element_init_G1(p->g1, pairing);
	element_init_G1(p->g2, pairing);
	element_init_G1(p->g3_left, pairing);
	element_init_G1(p->g3_right, pairing);
	for(i = 0; i < d_LEVEL; i++){
		element_init_G1(p->h_left[i], pairing);
		element_init_G1(p->h_right[i], pairing);
	}
	return p;
}

void element_to_file(element_t e, FILE* fp){
	int size;
	unsigned char buf[BUF_SIZE];

	size = element_to_bytes(buf, e);
	fprintf(fp, "%d\n", size);
	fwrite(buf, size, 1, fp);
}

void file_to_element(element_t* e, FILE* fp){
	int size;
	unsigned char buf[BUF_SIZE];

	fscanf(fp, "%d\n", &size);
	fread(buf, size, 1, fp);
	element_from_bytes(*e, buf);
}

void param_store(param* p){
	int i;
	FILE* fp = fopen("publickey.key", "w");

	element_to_file(p->g, fp);
	element_to_file(p->g1, fp);
	element_to_file(p->g2, fp);
	element_to_file(p->g3_left, fp);
	element_to_file(p->g3_right, fp);

	for(i = 0; i < d_LEVEL; i++){
		element_to_file(p->h_left[i], fp);
		element_to_file(p->h_right[i], fp);
	}
	fclose(fp);
}

void param_load(param* p){
	int i;
	FILE* fp = fopen("publickey.key", "r");
	if(!fp){ printf("Cannot find public key. Initial setup is required.\n"); exit(1); }

	file_to_element(&(p->g), fp);
	file_to_element(&(p->g1), fp);
	file_to_element(&(p->g2), fp);
	file_to_element(&(p->g3_left), fp);
	file_to_element(&(p->g3_right), fp);

	for(i = 0; i < d_LEVEL; i++){
		file_to_element(&(p->h_left[i]), fp);
		file_to_element(&(p->h_right[i]), fp);		
	}
	fclose(fp);
}

SK_j* init_SK_j(pairing_t pairing){
	int i;
	SK_j* sk_j;
	sk_j = (SK_j*)malloc(sizeof(SK_j));
	element_init_G1(sk_j->a0, pairing);
	element_init_G1(sk_j->a1, pairing);
	for(i = 0; i < d_LEVEL; i++)
		element_init_G1(sk_j->b[i], pairing);
	return sk_j;
}


void DecKey_store(DecKey* dk, unsigned char* filename){
	int i, j;
	FILE* fp = fopen(filename, "w");

	element_to_file(dk->SK_right[0], fp);
	element_to_file(dk->SK_right[1], fp);
	element_to_file(dk->SK_left[0], fp);
	element_to_file(dk->SK_left[1], fp);
	
	for(i = 0; i < d_LEVEL; i++){
		element_to_file(dk->SK_right_j[i]->a0, fp);
		element_to_file(dk->SK_right_j[i]->a1, fp);
		for(j = 0; j < d_LEVEL; j++) 
			element_to_file(dk->SK_right_j[i]->b[j], fp);

		element_to_file(dk->SK_left_j[i]->a0, fp);
		element_to_file(dk->SK_left_j[i]->a1, fp);
		for(j = 0; j < d_LEVEL; j++) 
			element_to_file(dk->SK_left_j[i]->b[j], fp);
	}
	fclose(fp);
}

void DecKey_load(DecKey* dk, unsigned char* filename){
	int i, j;
	FILE* fp = fopen(filename, "r");
	if(!fp){ printf("Cannot find decryption key. Keygen is required.\n"); exit(1); }

	file_to_element(dk->SK_right[0], fp);
	file_to_element(dk->SK_right[1], fp);
	file_to_element(dk->SK_left[0], fp);
	file_to_element(dk->SK_left[1], fp);
	
	for(i = 0; i < d_LEVEL; i++){
		file_to_element(dk->SK_right_j[i]->a0, fp);
		file_to_element(dk->SK_right_j[i]->a1, fp);
		for(j = 0; j < d_LEVEL; j++) 
			file_to_element(dk->SK_right_j[i]->b[j], fp);

		file_to_element(dk->SK_left_j[i]->a0, fp);
		file_to_element(dk->SK_left_j[i]->a1, fp);
		for(j = 0; j < d_LEVEL; j++) 
			file_to_element(dk->SK_left_j[i]->b[j], fp);
	}
	fclose(fp);
}

DecKey* init_DecKey(pairing_t pairing){
	int i;
	DecKey* dk;
	dk = (DecKey*)malloc(sizeof(DecKey));
	element_init_G1(dk->SK_right[0], pairing);
	element_init_G1(dk->SK_right[1], pairing);
	element_init_G1(dk->SK_left[0], pairing);
	element_init_G1(dk->SK_left[1], pairing);
	dk->SK_right_j = (SK_j**)malloc(sizeof(SK_j*) * d_LEVEL);
	dk->SK_left_j = (SK_j**)malloc(sizeof(SK_j*) * d_LEVEL);
	for(i = 0; i < d_LEVEL; i++){	
		dk->SK_right_j[i] = init_SK_j(pairing);
		dk->SK_left_j[i] = init_SK_j(pairing);
	}
	return dk;
}

void Hdr_store(Hdr* hdr, unsigned char* filename){
	int i;
	FILE* fp = fopen(filename, "w");

	element_to_file(hdr->CT, fp);
	element_to_file(hdr->C_right[0], fp);
	element_to_file(hdr->C_right[1], fp);
	element_to_file(hdr->C_left[0], fp);
	element_to_file(hdr->C_left[1], fp);
	
	fclose(fp);
}

void Hdr_load(Hdr* hdr, unsigned char* filename){
	int i;
	FILE* fp = fopen(filename, "r");
	if(!fp){ printf("Cannot find header(ciphertext). Encryption is required.\n"); exit(1); }

	file_to_element(&(hdr->CT), fp);
	file_to_element(&(hdr->C_right[0]), fp);
	file_to_element(&(hdr->C_right[1]), fp);
	file_to_element(&(hdr->C_left[0]), fp);
	file_to_element(&(hdr->C_left[1]), fp);
	
	fclose(fp);
}

Hdr* init_Hdr(pairing_t pairing){
	Hdr* hdr;
	hdr = (Hdr*)malloc(sizeof(Hdr));
	element_init_GT(hdr->CT, pairing);
	element_init_G1(hdr->C_right[0], pairing);
	element_init_G1(hdr->C_right[1], pairing);
	element_init_G1(hdr->C_left[0], pairing);
	element_init_G1(hdr->C_left[1], pairing);
	return hdr;
}

char* int_to_bitstring(int val){
	int i;
	char* bitstring = (char*)malloc(sizeof(char) * d_LEVEL);
	for(i = d_LEVEL - 1; i >= 0; i--){ 
		//if bit is 1, put '1'; otherwise put '0'
		bitstring[i] = '0' + (val & 0x01);
		val = (val >> 1);
	}
	return bitstring;
}

char* left_sibling(char* w_id, int j){
	int i;
	char* sibling = (char*)malloc(sizeof(char) * (j + 1));
	for(int i = 0; i < j; i++)
		sibling[i] = w_id[i];
	sibling[j] = '0';
	sibling[j + 1] = 0x00;
	return sibling;
}

char* right_sibling(char* w_id, int j){
	int i;
	char* sibling = (char*)malloc(sizeof(char) * (j + 1));
	for(int i = 0; i < j; i++)
		sibling[i] = w_id[i];
	sibling[j] = '1';
	sibling[j + 1] = 0x00;
	return sibling;
}

void FL(element_t* result, char* v_id, int length, param* p, pairing_t pairing){
	int i;
	//g3L * prod(1~l)hL[i]^v[i]
	element_set(*result, p->g3_left);
	for(i = 0; i < length; i++){
		if(v_id[i] == '1')
			element_mul(*result, *result, p->h_left[i]);
	}
}

void FR(element_t* result, char* v_id, int length, param* p, pairing_t pairing){
	int i;
	//g3R * prod(1~l)hR[i]^v[i]
	element_set(*result, p->g3_right);
	for(i = 0; i < length; i++){
		if(v_id[i] == '1')
			element_mul(*result, *result, p->h_right[i]);
	}
}

void setup(param* p, pairing_t pairing, element_t* msk){
	int i;
	element_t alpha;

	//assign params
	element_init_Zr(alpha, pairing);
	element_random(alpha);
	element_random(p->g);
	element_pow_zn(p->g1, p->g, alpha);
	element_random(p->g2);
	element_random(p->g3_left);
	element_random(p->g3_right);
	for(i = 0; i < d_LEVEL; i++){
		element_random(p->h_left[i]);
		element_random(p->h_right[i]);
	}

	//msk = g2^alpha
	element_pow_zn(*msk, p->g2, alpha);
	element_clear(alpha);
}

DecKey* pvkgen(int id, element_t msk, param* p, pairing_t pairing){
	int i, j;
	char* w_id;
	DecKey* dk;
	element_t msk_right;
	element_t msk_left;
	element_t fl;
	element_t fr;
	element_t alpha_w;
	element_t r_w;
	element_t r_j;

	//convert id to bitstring
	w_id = int_to_bitstring(id);

	dk = init_DecKey(pairing);
	element_init_G1(msk_right, pairing);
	element_init_G1(msk_left, pairing);
	element_init_G1(fl, pairing);
	element_init_G1(fr, pairing);
	element_init_Zr(alpha_w, pairing);
	element_init_Zr(r_w, pairing);
	element_init_Zr(r_j, pairing);

	element_random(alpha_w);
	//msk_r = g2^alpha_w, msk_l = g2^alpha-alpha_w)
	element_pow_zn(msk_right, p->g2, alpha_w);
	element_div(msk_left, msk, msk_right);

	element_random(r_w);
	//SK_w,R = [g2^alpha_w * (FR(w)^r_w), g^r_w]
	FR(&fr, w_id, d_LEVEL, p, pairing);
	element_pow_zn(dk->SK_right[0], fr, r_w);
	element_mul(dk->SK_right[0], dk->SK_right[0], msk_right);
	element_pow_zn(dk->SK_right[1], p->g, r_w);

	//SK_w,L = [g2^(alpha-alpha_w) * (FL(w)^r_w), g^r_w]
	FL(&fl, w_id, d_LEVEL, p, pairing);
	element_pow_zn(dk->SK_left[0], fl, r_w);
	element_mul(dk->SK_left[0], dk->SK_left[0], msk_left);
	element_pow_zn(dk->SK_left[1], p->g, r_w);

	//SK_j,RS = g2^(alpha_w) * FR(w_j,RS)^r_j, g^r_j, h series
	for(j = 0; j < d_LEVEL; j++){
		element_random(r_j);
		//right sibling
		if(w_id[j] == '0'){
			//a0 = g2^(alpha_w) * FR(w_j,RS)^r_j
			FR(&fr, right_sibling(w_id, j), j + 1, p, pairing);
			element_pow_zn(dk->SK_right_j[j]->a0, fr, r_j);
			element_mul(dk->SK_right_j[j]->a0, dk->SK_right_j[j]->a0, msk_right);

			//a1 = g^r_j
			element_pow_zn(dk->SK_right_j[j]->a1, p->g, r_j);

			//h series: h_j+1,r ^ r_j ~ h_d,r ^ r_j
			for(i = j + 1; i < d_LEVEL; i++)
				element_pow_zn(dk->SK_right_j[j]->b[i], p->h_right[i], r_j);			
		}
		//left_sibling
		else{
			//a0 = g2^(alpha-alpha_w) * FL(w_j,LS)^r_j
			FL(&fl, left_sibling(w_id, j), j + 1, p, pairing); 
			element_pow_zn(dk->SK_left_j[j]->a0, fl, r_j);
			element_mul(dk->SK_left_j[j]->a0, dk->SK_left_j[j]->a0, msk_left);

			//a1 = g^r_j
			element_pow_zn(dk->SK_left_j[j]->a1, p->g, r_j);

			//h series: h_j+1,l ^ r_j ~ h_d,l ^ r_j
			for(i = j + 1; i < d_LEVEL; i++)
				element_pow_zn(dk->SK_left_j[j]->b[i], p->h_left[i], r_j);
		}
	}

	element_clear(msk_right);
	element_clear(msk_left);
	element_clear(fl);
	element_clear(fr);
	element_clear(alpha_w);
	element_clear(r_w);
	element_clear(r_j);
	return dk;
}

Hdr* encrypt(unsigned char* msg, int left, int right, param* p, pairing_t pairing){
	int i, j;
	char* left_bitstring;
	char* right_bitstring;
	Hdr* hdr;
	element_t gamma;
	element_t fl;
	element_t fr;
	element_t K_sym;
	element_t M;

	//convert left, right from integer to binary string
	left_bitstring = int_to_bitstring(left);
	right_bitstring = int_to_bitstring(right);

	element_init_Zr(gamma, pairing);
	element_init_G1(fl, pairing);
	element_init_G1(fr, pairing);
	element_init_GT(K_sym, pairing);
	element_init_GT(M, pairing);

	hdr = init_Hdr(pairing);
	element_random(gamma);

	//C_l = g^gamma, FL(l_j)^gamma_j
	element_pow_zn(hdr->C_left[0], p->g, gamma);
	FL(&fl, left_bitstring, d_LEVEL, p, pairing);
	element_pow_zn(hdr->C_left[1], fl, gamma);

	///C_r = g^gamma, FR(r_j)^gamma_j
	element_pow_zn(hdr->C_right[0], p->g, gamma);
	FR(&fr, right_bitstring, d_LEVEL, p, pairing);
	element_pow_zn(hdr->C_right[1], fr, gamma);

	//K_j = e(g1,g2)^gamma
	pairing_apply(K_sym, p->g1, p->g2, pairing);
	element_pow_zn(K_sym, K_sym, gamma);

	//symmetric encryption: Enc(M, K_j)
	element_from_bytes(M, msg);
	//Instead of symmetric encryption, we just multiply K_sym
	element_mul(hdr->CT, K_sym, M);

	element_clear(gamma);
	element_clear(fl);
	element_clear(fr);
	element_clear(K_sym);
	element_clear(M);
	return hdr;
}

element_t* left_keyder(char* w_id, char* lowbound, SK_j** SK_node, param* p, pairing_t pairing){
	int i, j;
	element_t t;
	element_t fl;
	element_t temp;
	element_t* SK_lowbound = (element_t*)malloc(sizeof(element_t) * 2);

	//find existing node SK which belongs to D_w,L
	for(j = 0; j < d_LEVEL; j++)
		if(w_id[j] != lowbound[j]) break;
	if(j == d_LEVEL) j--;

	element_init_Zr(t, pairing);
	element_init_G1(fl, pairing);
	element_init_G1(temp, pairing);
	element_init_G1(SK_lowbound[0], pairing);
	element_init_G1(SK_lowbound[1], pairing);
	element_set(SK_lowbound[0], SK_node[j]->a0);
	element_set(SK_lowbound[1], SK_node[j]->a1);

	//key delegation:**b[i]
	element_random(t);
	for(i = j; i < d_LEVEL; i++){
		if(lowbound[i] == '1')
			element_mul(SK_lowbound[0], SK_lowbound[0], SK_node[j]->b[i]);
	}
	
	//SK_left->a0 = a0 * b_(i+1)^bit * FL^t
	FL(&fl, lowbound, d_LEVEL, p, pairing);
	element_pow_zn(temp, fl, t);
	element_mul(SK_lowbound[0], SK_lowbound[0], temp);

	//SK_left->a1 = a1 * g^t
	element_pow_zn(temp, p->g, t);
	element_mul(SK_lowbound[1], SK_lowbound[1], temp);
	
	element_clear(t);
	element_clear(fl);
	element_clear(temp);
	return SK_lowbound; 
}

element_t* right_keyder(char* w_id, char* upbound, SK_j** SK_node, param* p, pairing_t pairing){
	int i, j;
	element_t t;
	element_t fr;
	element_t temp;
	element_t* SK_upbound = (element_t*)malloc(sizeof(element_t) * 2);

	//find existing node SK which belongs to D_w,R
	for(j = 0; j < d_LEVEL; j++)
		if(w_id[j] != upbound[j]) break;
	if(j == d_LEVEL) j--;

	element_init_Zr(t, pairing);
	element_init_G1(fr, pairing);
	element_init_G1(temp, pairing);
	element_init_G1(SK_upbound[0], pairing);
	element_init_G1(SK_upbound[1], pairing);
	element_set(SK_upbound[0], SK_node[j]->a0);
	element_set(SK_upbound[1], SK_node[j]->a1);

	//key delegation:**b[i]
	element_random(t);
	for(i = j; i < d_LEVEL; i++){
		if(upbound[i] == '1')
			element_mul(SK_upbound[0], SK_upbound[0], SK_node[j]->b[i]);
	}
	
	//SK_right->a0 = a0 * b_(i+1)^bit * FR^t
	FR(&fr, upbound, d_LEVEL, p, pairing);
	element_pow_zn(temp, fr, t);
	element_mul(SK_upbound[0], SK_upbound[0], temp);

	//SK_right->a1 = a1 * g^t
	element_pow_zn(temp, p->g, t);
	element_mul(SK_upbound[1], SK_upbound[1], temp);
	
	element_clear(t);
	element_clear(fr);
	element_clear(temp);
	return SK_upbound; 
}

unsigned char* decrypt(Hdr* hdr, DecKey* dk, int left, int right, int id, param* p, pairing_t pairing){
	int i, j;
	char* w_id;
	char* left_bitstring;
	char* right_bitstring;
	unsigned char* msg;
	element_t K_sym;
	element_t M;
	element_t temp1, temp2;
	element_t tempL, tempR;
	element_t* lk;
	element_t* rk;
	
	//convert left, right, id from integer to binary string
	left_bitstring = int_to_bitstring(left);
	right_bitstring = int_to_bitstring(right);
	w_id = int_to_bitstring(id);

	element_init_GT(K_sym, pairing);
	element_init_GT(M, pairing);
	element_init_GT(temp1, pairing);
	element_init_GT(temp2, pairing);
	element_init_GT(tempL, pairing);
	element_init_GT(tempR, pairing);

	rk = right_keyder(w_id, right_bitstring, dk->SK_right_j, p, pairing);
	lk = left_keyder(w_id, left_bitstring, dk->SK_left_j, p, pairing);
	
	//e(g^gamma, g2^(alpha_w) * FR^r'' / e(g^r'', FR^gamma_j)
	pairing_apply(temp1, hdr->C_right[0], rk[0], pairing);
	pairing_apply(temp2, hdr->C_right[1], rk[1], pairing);
	element_div(tempR, temp1, temp2);

	//e(g^gamma, g2^(alpha-alpha_w) * FL^r' / e(g^r', FL^gamma_j)
	pairing_apply(temp1, hdr->C_left[0], lk[0], pairing);
	pairing_apply(temp2, hdr->C_left[1], lk[1], pairing);
	element_div(tempL, temp1, temp2);

	//K_sym = e(g1,g2)^gamma
	element_mul(K_sym, tempL, tempR);

	//symmetric decryption: Dec(M, K_j)
	element_div(M, hdr->CT, K_sym);
	msg = (char*)malloc(sizeof(char) * MSG_SIZE);
	element_to_bytes(msg, M);

	element_clear(temp1);
	element_clear(temp2);
	element_clear(tempL);
	element_clear(tempR);
	element_clear(K_sym);
	element_clear(M);
	return msg;
}

void print_help(){
	printf("Usage: ./interval option\n");
	printf("option:\n");
	printf("setup - setup msk_out_filename\n");
	printf("	ex: ./interval setup sample_msk.key\n");
	printf("keygen - keygen id msk_in_filename dk_out_filename\n");
	printf("	ex: ./interval keygen 3 sample_msk.key sample_deckey.key\n");
	printf("encrypt - encrypt msg_filename interval_left interval_right hdr_out_filename\n");
	printf("	ex: ./interval encrypt sample_msg.dat 1 5 sample_hdr.dat\n");
	printf("decrypt - decrypt hdr_in_filename dk_in_filename interval_left interval_right id msg_out_filename\n");
	printf("	ex: ./interval decrypt sample_hdr.dat sample_deckey.key 1 5 3 sample_msg.dat\n");
	exit(1);
}

int main(int argc, char* argv[]){
	int i;
	time_t timestamp;

	pairing_t pairing;
	char pbc_param[BUF_SIZE];
	size_t pbc_size;

	element_t msk;
	DecKey* dk;
	Hdr* hdr;
	param* p;

	IntervalSet* S;
	int k_sets;
	FILE* fp;

	unsigned char M[MSG_SIZE];
	unsigned char* msg_result;

	fp = fopen("param", "r");
	if(!fp){ printf("No PBC param file.\n"); exit(1); }
	pbc_size = fread(pbc_param, 1, BUF_SIZE, fp);
	if(!pbc_size){ printf("Inappropriate PBC param file.\n"); exit(1); }
	pairing_init_set_buf(pairing, pbc_param, pbc_size);
	fclose(fp);

	if(argc < 2) print_help();

	//SETUP: setup msk_out
	if(!strcmp(argv[1], "setup")){
		if(argc != 3) print_help();
		timestamp = clock();
		
		p = init_param(pairing);
		element_init_G1(msk, pairing);
		setup(p, pairing, &msk);
		param_store(p);
		fp = fopen(argv[2], "w");
		element_to_file(msk, fp);
		fclose(fp);
		
		printf("Setup completed in %f sec.\n", (float)(clock() - timestamp) / CLOCKS_PER_SEC);
	}

	//KEYGEN: k id msk_in dk_out
	else if(!strcmp(argv[1], "keygen")){
		if(argc != 5) print_help();
		timestamp = clock();

		p = init_param(pairing);
		param_load(p);
		
		element_init_G1(msk, pairing);
		fp = fopen(argv[3], "r");
		file_to_element(&msk, fp);
		fclose(fp);

		dk = pvkgen(atoi(argv[2]), msk, p, pairing);
		DecKey_store(dk, argv[4]);
		
		printf("KeyGen for id %d completed in %f sec.\n", atoi(argv[2]), (float)(clock() - timestamp) / CLOCKS_PER_SEC);
	}

	//ENCRYPT: e msg left right hdr_out
	else if(!strcmp(argv[1], "encrypt")){
		if(argc != 6) print_help();
		timestamp = clock();

		p = init_param(pairing);
		param_load(p);
	
		fp = fopen(argv[2], "r");
		fread(M, 1, BUF_SIZE, fp);
		fclose(fp);		

		hdr = encrypt(M, atoi(argv[3]), atoi(argv[4]), p, pairing);
		Hdr_store(hdr, argv[5]);

		printf("Encryption for interval [%d ~ %d] completed in %f sec.\n", atoi(argv[3]), atoi(argv[4]), (float)(clock() - timestamp) / CLOCKS_PER_SEC);
	}

	//DECRYPT: d hdr_in dk_in left right id msg_out
	else if(!strcmp(argv[1], "decrypt")){
		if(argc != 8) print_help();
		if(atoi(argv[6]) < atoi(argv[4]) || atoi(argv[6]) > atoi(argv[5])){ printf("ID not in range.\n"); exit(1); }

		timestamp = clock();

		p = init_param(pairing);
		param_load(p);

		hdr = init_Hdr(pairing);
		Hdr_load(hdr, argv[2]);

		dk = init_DecKey(pairing);
		DecKey_load(dk, argv[3]);

		msg_result = decrypt(hdr, dk, atoi(argv[4]), atoi(argv[5]), atoi(argv[6]), p, pairing);
		fp = fopen(argv[7], "w");
		fprintf(fp, "%s", msg_result);		
		fclose(fp);

		printf("Decryption for interval [%d ~ %d] completed in %f sec.\n", atoi(argv[4]), atoi(argv[5]), (float)(clock() - timestamp) / CLOCKS_PER_SEC);
	}

	else print_help();

	return 0;
}
















