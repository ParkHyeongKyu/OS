#define E 17
#define F 14
#define FRACTION (1<<F)

int convert_to_fp(int n);
int convert_to_int_round_zero(int x);
int convert_to_int_round_nearest(int x);
int add_fp_fp(int x, int y);
int add_fp_int(int x, int n);
int sub_fp_fp(int x, int y);
int sub_fp_int(int x, int n);
int mul_fp_fp(int x, int y);
int mul_fp_int(int x, int n);
int div_fp_fp(int x, int y);
int div_fp_n(int x, int n);

int convert_to_fp(int n){
    // Convert n to fixed point
    return n * (FRACTION);
}

int convert_to_int_round_zero(int x){
    // Convert x to integer (rounding toward zero)
    return x / (FRACTION);
}

int convert_to_int_round_nearest(int x){
    // Convert x to integer (rounding to nearest)
    if (x >= 0){
        return (x + (FRACTION)/2)/(FRACTION);
    }
    else{
        return (x - (FRACTION/2))/(FRACTION);
    }
}

int add_fp_fp(int x, int y){
    // return fp + fp
    return x + y;
}

int add_fp_int(int x, int n){
    // return fp + int
    return x + n * (FRACTION);
}

int sub_fp_fp(int x, int y){
    // return fp - fp
    return x - y;
}

int sub_fp_int(int x, int n){
    // return fp - int
    return x - n * (FRACTION);
}

int mul_fp_fp(int x, int y){
    // return fp * fp
    return ((int64_t)x) * y / (FRACTION);
}

int mul_fp_int(int x, int n){
    // return fp * int
    return x * n;
}

int div_fp_fp(int x, int y){
    // return fp / fp
    return ((int64_t)x) * (FRACTION) / y;
}

int div_fp_n(int x, int n){
    // return fp / int
    return x / n;
}