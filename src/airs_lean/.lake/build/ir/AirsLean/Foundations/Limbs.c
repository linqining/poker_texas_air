// Lean compiler output
// Module: AirsLean.Foundations.Limbs
// Imports: public import Init public meta import Init public import AirsLean.Foundations.M31
#include <lean/lean.h>
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wunused-label"
#elif defined(__GNUC__) && !defined(__CLANG__)
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-label"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#endif
#ifdef __cplusplus
extern "C" {
#endif
lean_object* lp_mathlib_ZMod_val(lean_object*, lean_object*);
lean_object* lean_nat_mul(lean_object*, lean_object*);
lean_object* lean_nat_add(lean_object*, lean_object*);
lean_object* lp_mathlib_ZMod_instField___redArg(lean_object*);
lean_object* lean_nat_mod(lean_object*, lean_object*);
lean_object* lp_mathlib_Field_toDivisionRing___redArg(lean_object*);
lean_object* lp_mathlib_Ring_toAddGroupWithOne___redArg(lean_object*);
lean_object* lean_nat_shiftr(lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_B16;
static lean_once_cell_t lp_airs__lean_AirsLean_B64___closed__0_once = LEAN_ONCE_CELL_INITIALIZER;
static lean_object* lp_airs__lean_AirsLean_B64___closed__0;
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_B64;
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_decode(lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_decode___boxed(lean_object*);
static lean_once_cell_t lp_airs__lean_Nat_cast___at___00AirsLean_encode_spec__0___closed__0_once = LEAN_ONCE_CELL_INITIALIZER;
static lean_object* lp_airs__lean_Nat_cast___at___00AirsLean_encode_spec__0___closed__0;
static lean_once_cell_t lp_airs__lean_Nat_cast___at___00AirsLean_encode_spec__0___closed__1_once = LEAN_ONCE_CELL_INITIALIZER;
static lean_object* lp_airs__lean_Nat_cast___at___00AirsLean_encode_spec__0___closed__1;
LEAN_EXPORT lean_object* lp_airs__lean_Nat_cast___at___00AirsLean_encode_spec__0(lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_encode(lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_encode___boxed(lean_object*);
static lean_object* _init_lp_airs__lean_AirsLean_B16(void){
_start:
{
lean_object* v___x_1_; 
v___x_1_ = lean_unsigned_to_nat(65536u);
return v___x_1_;
}
}
static lean_object* _init_lp_airs__lean_AirsLean_B64___closed__0(void){
_start:
{
lean_object* v___x_2_; 
v___x_2_ = lean_cstr_to_nat("18446744073709551616");
return v___x_2_;
}
}
static lean_object* _init_lp_airs__lean_AirsLean_B64(void){
_start:
{
lean_object* v___x_3_; 
v___x_3_ = lean_obj_once(&lp_airs__lean_AirsLean_B64___closed__0, &lp_airs__lean_AirsLean_B64___closed__0_once, _init_lp_airs__lean_AirsLean_B64___closed__0);
return v___x_3_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_decode(lean_object* v_l_4_){
_start:
{
lean_object* v_l0_5_; lean_object* v_l1_6_; lean_object* v_l2_7_; lean_object* v_l3_8_; lean_object* v___x_9_; lean_object* v___x_10_; lean_object* v___x_11_; lean_object* v___x_12_; lean_object* v___x_13_; lean_object* v___x_14_; lean_object* v___x_15_; lean_object* v___x_16_; lean_object* v___x_17_; lean_object* v___x_18_; lean_object* v___x_19_; lean_object* v___x_20_; lean_object* v___x_21_; lean_object* v___x_22_; 
v_l0_5_ = lean_ctor_get(v_l_4_, 0);
v_l1_6_ = lean_ctor_get(v_l_4_, 1);
v_l2_7_ = lean_ctor_get(v_l_4_, 2);
v_l3_8_ = lean_ctor_get(v_l_4_, 3);
v___x_9_ = lean_unsigned_to_nat(2147483647u);
v___x_10_ = lp_mathlib_ZMod_val(v___x_9_, v_l0_5_);
v___x_11_ = lean_unsigned_to_nat(65536u);
v___x_12_ = lp_mathlib_ZMod_val(v___x_9_, v_l1_6_);
v___x_13_ = lean_nat_mul(v___x_11_, v___x_12_);
lean_dec(v___x_12_);
v___x_14_ = lean_nat_add(v___x_10_, v___x_13_);
lean_dec(v___x_13_);
lean_dec(v___x_10_);
v___x_15_ = lean_cstr_to_nat("4294967296");
v___x_16_ = lp_mathlib_ZMod_val(v___x_9_, v_l2_7_);
v___x_17_ = lean_nat_mul(v___x_15_, v___x_16_);
lean_dec(v___x_16_);
v___x_18_ = lean_nat_add(v___x_14_, v___x_17_);
lean_dec(v___x_17_);
lean_dec(v___x_14_);
v___x_19_ = lean_cstr_to_nat("281474976710656");
v___x_20_ = lp_mathlib_ZMod_val(v___x_9_, v_l3_8_);
v___x_21_ = lean_nat_mul(v___x_19_, v___x_20_);
lean_dec(v___x_20_);
v___x_22_ = lean_nat_add(v___x_18_, v___x_21_);
lean_dec(v___x_21_);
lean_dec(v___x_18_);
return v___x_22_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_decode___boxed(lean_object* v_l_23_){
_start:
{
lean_object* v_res_24_; 
v_res_24_ = lp_airs__lean_AirsLean_decode(v_l_23_);
lean_dec_ref(v_l_23_);
return v_res_24_;
}
}
static lean_object* _init_lp_airs__lean_Nat_cast___at___00AirsLean_encode_spec__0___closed__0(void){
_start:
{
lean_object* v___x_25_; lean_object* v___x_26_; 
v___x_25_ = lean_unsigned_to_nat(2147483647u);
v___x_26_ = lp_mathlib_ZMod_instField___redArg(v___x_25_);
return v___x_26_;
}
}
static lean_object* _init_lp_airs__lean_Nat_cast___at___00AirsLean_encode_spec__0___closed__1(void){
_start:
{
lean_object* v___x_27_; lean_object* v___x_28_; 
v___x_27_ = lean_obj_once(&lp_airs__lean_Nat_cast___at___00AirsLean_encode_spec__0___closed__0, &lp_airs__lean_Nat_cast___at___00AirsLean_encode_spec__0___closed__0_once, _init_lp_airs__lean_Nat_cast___at___00AirsLean_encode_spec__0___closed__0);
v___x_28_ = lp_mathlib_Field_toDivisionRing___redArg(v___x_27_);
return v___x_28_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_Nat_cast___at___00AirsLean_encode_spec__0(lean_object* v_a_29_){
_start:
{
lean_object* v___x_30_; lean_object* v_toRing_31_; lean_object* v___x_32_; lean_object* v_toAddMonoidWithOne_33_; lean_object* v_toNatCast_34_; lean_object* v___x_35_; 
v___x_30_ = lean_obj_once(&lp_airs__lean_Nat_cast___at___00AirsLean_encode_spec__0___closed__1, &lp_airs__lean_Nat_cast___at___00AirsLean_encode_spec__0___closed__1_once, _init_lp_airs__lean_Nat_cast___at___00AirsLean_encode_spec__0___closed__1);
v_toRing_31_ = lean_ctor_get(v___x_30_, 0);
lean_inc_ref(v_toRing_31_);
v___x_32_ = lp_mathlib_Ring_toAddGroupWithOne___redArg(v_toRing_31_);
v_toAddMonoidWithOne_33_ = lean_ctor_get(v___x_32_, 1);
lean_inc_ref(v_toAddMonoidWithOne_33_);
lean_dec_ref(v___x_32_);
v_toNatCast_34_ = lean_ctor_get(v_toAddMonoidWithOne_33_, 0);
lean_inc(v_toNatCast_34_);
lean_dec_ref(v_toAddMonoidWithOne_33_);
v___x_35_ = lean_apply_1(v_toNatCast_34_, v_a_29_);
return v___x_35_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_encode(lean_object* v_v_36_){
_start:
{
lean_object* v___x_37_; lean_object* v___x_38_; lean_object* v___x_39_; lean_object* v___x_40_; lean_object* v___x_41_; lean_object* v___x_42_; lean_object* v___x_43_; lean_object* v___x_44_; lean_object* v___x_45_; lean_object* v___x_46_; lean_object* v___x_47_; lean_object* v___x_48_; lean_object* v___x_49_; lean_object* v___x_50_; lean_object* v___x_51_; lean_object* v___x_52_; 
v___x_37_ = lean_unsigned_to_nat(65536u);
v___x_38_ = lean_nat_mod(v_v_36_, v___x_37_);
v___x_39_ = lp_airs__lean_Nat_cast___at___00AirsLean_encode_spec__0(v___x_38_);
v___x_40_ = lean_unsigned_to_nat(16u);
v___x_41_ = lean_nat_shiftr(v_v_36_, v___x_40_);
v___x_42_ = lean_nat_mod(v___x_41_, v___x_37_);
lean_dec(v___x_41_);
v___x_43_ = lp_airs__lean_Nat_cast___at___00AirsLean_encode_spec__0(v___x_42_);
v___x_44_ = lean_unsigned_to_nat(32u);
v___x_45_ = lean_nat_shiftr(v_v_36_, v___x_44_);
v___x_46_ = lean_nat_mod(v___x_45_, v___x_37_);
lean_dec(v___x_45_);
v___x_47_ = lp_airs__lean_Nat_cast___at___00AirsLean_encode_spec__0(v___x_46_);
v___x_48_ = lean_unsigned_to_nat(48u);
v___x_49_ = lean_nat_shiftr(v_v_36_, v___x_48_);
v___x_50_ = lean_nat_mod(v___x_49_, v___x_37_);
lean_dec(v___x_49_);
v___x_51_ = lp_airs__lean_Nat_cast___at___00AirsLean_encode_spec__0(v___x_50_);
v___x_52_ = lean_alloc_ctor(0, 4, 0);
lean_ctor_set(v___x_52_, 0, v___x_39_);
lean_ctor_set(v___x_52_, 1, v___x_43_);
lean_ctor_set(v___x_52_, 2, v___x_47_);
lean_ctor_set(v___x_52_, 3, v___x_51_);
return v___x_52_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_encode___boxed(lean_object* v_v_53_){
_start:
{
lean_object* v_res_54_; 
v_res_54_ = lp_airs__lean_AirsLean_encode(v_v_53_);
lean_dec(v_v_53_);
return v_res_54_;
}
}
lean_object* initialize_Init(uint8_t builtin);
lean_object* initialize_Init(uint8_t builtin);
lean_object* initialize_airs__lean_AirsLean_Foundations_M31(uint8_t builtin);
static bool _G_initialized = false;
LEAN_EXPORT lean_object* initialize_airs__lean_AirsLean_Foundations_Limbs(uint8_t builtin) {
lean_object * res;
if (_G_initialized) return lean_io_result_mk_ok(lean_box(0));
_G_initialized = true;
res = initialize_Init(builtin);
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_Init(builtin);
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_airs__lean_AirsLean_Foundations_M31(builtin);
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
lp_airs__lean_AirsLean_B16 = _init_lp_airs__lean_AirsLean_B16();
lean_mark_persistent(lp_airs__lean_AirsLean_B16);
lp_airs__lean_AirsLean_B64 = _init_lp_airs__lean_AirsLean_B64();
lean_mark_persistent(lp_airs__lean_AirsLean_B64);
return lean_io_result_mk_ok(lean_box(0));
}
#ifdef __cplusplus
}
#endif
