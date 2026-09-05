// Lean compiler output
// Module: AirsLean.Custody.ChipState
// Imports: public import Init public meta import Init public import AirsLean.Soundness.Composition
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
lean_object* l_List_finRange(lean_object*);
lean_object* lean_nat_add(lean_object*, lean_object*);
lean_object* lp_mathlib_Finset_sum___at___00Fin_accumulate_spec__0___redArg(lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_custodyTotal___lam__0(lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_custodyTotal___lam__1(lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_custodyTotal___lam__2(lean_object*, lean_object*);
static lean_once_cell_t lp_airs__lean_AirsLean_custodyTotal___closed__0_once = LEAN_ONCE_CELL_INITIALIZER;
static lean_object* lp_airs__lean_AirsLean_custodyTotal___closed__0;
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_custodyTotal(lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_balance(lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_custodyTotal___lam__0(lean_object* v_s_1_, lean_object* v_k_2_){
_start:
{
lean_object* v_seats_3_; lean_object* v___x_4_; lean_object* v_stack_5_; 
v_seats_3_ = lean_ctor_get(v_s_1_, 0);
lean_inc_ref(v_seats_3_);
lean_dec_ref(v_s_1_);
v___x_4_ = lean_apply_1(v_seats_3_, v_k_2_);
v_stack_5_ = lean_ctor_get(v___x_4_, 0);
lean_inc(v_stack_5_);
lean_dec_ref(v___x_4_);
return v_stack_5_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_custodyTotal___lam__1(lean_object* v_seats_6_, lean_object* v_k_7_){
_start:
{
lean_object* v___x_8_; lean_object* v_bet_9_; 
v___x_8_ = lean_apply_1(v_seats_6_, v_k_7_);
v_bet_9_ = lean_ctor_get(v___x_8_, 1);
lean_inc(v_bet_9_);
lean_dec_ref(v___x_8_);
return v_bet_9_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_custodyTotal___lam__2(lean_object* v_seats_10_, lean_object* v_k_11_){
_start:
{
lean_object* v___x_12_; lean_object* v_pendingAddon_13_; 
v___x_12_ = lean_apply_1(v_seats_10_, v_k_11_);
v_pendingAddon_13_ = lean_ctor_get(v___x_12_, 3);
lean_inc(v_pendingAddon_13_);
lean_dec_ref(v___x_12_);
return v_pendingAddon_13_;
}
}
static lean_object* _init_lp_airs__lean_AirsLean_custodyTotal___closed__0(void){
_start:
{
lean_object* v___x_14_; lean_object* v___x_15_; 
v___x_14_ = lean_unsigned_to_nat(9u);
v___x_15_ = l_List_finRange(v___x_14_);
return v___x_15_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_custodyTotal(lean_object* v_s_16_){
_start:
{
lean_object* v_seats_17_; lean_object* v_pot_18_; lean_object* v_chipPool_19_; lean_object* v___f_20_; lean_object* v___x_21_; lean_object* v___x_22_; lean_object* v___f_23_; lean_object* v___f_24_; lean_object* v___x_25_; lean_object* v___x_26_; lean_object* v___x_27_; lean_object* v___x_28_; lean_object* v___x_29_; lean_object* v___x_30_; 
v_seats_17_ = lean_ctor_get(v_s_16_, 0);
lean_inc_ref_n(v_seats_17_, 2);
v_pot_18_ = lean_ctor_get(v_s_16_, 1);
lean_inc(v_pot_18_);
v_chipPool_19_ = lean_ctor_get(v_s_16_, 2);
lean_inc(v_chipPool_19_);
v___f_20_ = lean_alloc_closure((void*)(lp_airs__lean_AirsLean_custodyTotal___lam__0), 2, 1);
lean_closure_set(v___f_20_, 0, v_s_16_);
v___x_21_ = lean_obj_once(&lp_airs__lean_AirsLean_custodyTotal___closed__0, &lp_airs__lean_AirsLean_custodyTotal___closed__0_once, _init_lp_airs__lean_AirsLean_custodyTotal___closed__0);
v___x_22_ = lp_mathlib_Finset_sum___at___00Fin_accumulate_spec__0___redArg(v___x_21_, v___f_20_);
v___f_23_ = lean_alloc_closure((void*)(lp_airs__lean_AirsLean_custodyTotal___lam__1), 2, 1);
lean_closure_set(v___f_23_, 0, v_seats_17_);
v___f_24_ = lean_alloc_closure((void*)(lp_airs__lean_AirsLean_custodyTotal___lam__2), 2, 1);
lean_closure_set(v___f_24_, 0, v_seats_17_);
v___x_25_ = lp_mathlib_Finset_sum___at___00Fin_accumulate_spec__0___redArg(v___x_21_, v___f_23_);
v___x_26_ = lean_nat_add(v___x_22_, v___x_25_);
lean_dec(v___x_25_);
lean_dec(v___x_22_);
v___x_27_ = lean_nat_add(v___x_26_, v_pot_18_);
lean_dec(v_pot_18_);
lean_dec(v___x_26_);
v___x_28_ = lean_nat_add(v___x_27_, v_chipPool_19_);
lean_dec(v_chipPool_19_);
lean_dec(v___x_27_);
v___x_29_ = lp_mathlib_Finset_sum___at___00Fin_accumulate_spec__0___redArg(v___x_21_, v___f_24_);
v___x_30_ = lean_nat_add(v___x_28_, v___x_29_);
lean_dec(v___x_29_);
lean_dec(v___x_28_);
return v___x_30_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_balance(lean_object* v_s_31_, lean_object* v_p_32_){
_start:
{
lean_object* v_seats_33_; lean_object* v___x_34_; lean_object* v_stack_35_; lean_object* v_bet_36_; lean_object* v_pendingAddon_37_; lean_object* v___x_38_; lean_object* v___x_39_; 
v_seats_33_ = lean_ctor_get(v_s_31_, 0);
lean_inc_ref(v_seats_33_);
lean_dec_ref(v_s_31_);
v___x_34_ = lean_apply_1(v_seats_33_, v_p_32_);
v_stack_35_ = lean_ctor_get(v___x_34_, 0);
lean_inc(v_stack_35_);
v_bet_36_ = lean_ctor_get(v___x_34_, 1);
lean_inc(v_bet_36_);
v_pendingAddon_37_ = lean_ctor_get(v___x_34_, 3);
lean_inc(v_pendingAddon_37_);
lean_dec_ref(v___x_34_);
v___x_38_ = lean_nat_add(v_stack_35_, v_bet_36_);
lean_dec(v_bet_36_);
lean_dec(v_stack_35_);
v___x_39_ = lean_nat_add(v___x_38_, v_pendingAddon_37_);
lean_dec(v_pendingAddon_37_);
lean_dec(v___x_38_);
return v___x_39_;
}
}
lean_object* initialize_Init(uint8_t builtin);
lean_object* initialize_Init(uint8_t builtin);
lean_object* initialize_airs__lean_AirsLean_Soundness_Composition(uint8_t builtin);
static bool _G_initialized = false;
LEAN_EXPORT lean_object* initialize_airs__lean_AirsLean_Custody_ChipState(uint8_t builtin) {
lean_object * res;
if (_G_initialized) return lean_io_result_mk_ok(lean_box(0));
_G_initialized = true;
res = initialize_Init(builtin);
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_Init(builtin);
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_airs__lean_AirsLean_Soundness_Composition(builtin);
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
return lean_io_result_mk_ok(lean_box(0));
}
#ifdef __cplusplus
}
#endif
