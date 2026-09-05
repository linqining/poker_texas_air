// Lean compiler output
// Module: AirsLean.Censorship.ActionLog
// Imports: public import Init public meta import Init public import AirsLean.Censorship.ActionSig
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
lean_object* l_List_reverse___redArg(lean_object*);
uint8_t lean_nat_dec_eq(lean_object*, lean_object*);
LEAN_EXPORT uint8_t lp_airs__lean_AirsLean_instDecidableEqLogEntry_decEq(lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_instDecidableEqLogEntry_decEq___boxed(lean_object*, lean_object*);
LEAN_EXPORT uint8_t lp_airs__lean_AirsLean_instDecidableEqLogEntry(lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_instDecidableEqLogEntry___boxed(lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_List_filterTR_loop___at___00AirsLean_playerSeqs_spec__0(lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_List_filterTR_loop___at___00AirsLean_playerSeqs_spec__0___boxed(lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_List_mapTR_loop___at___00AirsLean_playerSeqs_spec__1(lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_playerSeqs(lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_playerSeqs___boxed(lean_object*, lean_object*);
LEAN_EXPORT uint8_t lp_airs__lean_AirsLean_instDecidableEqLogEntry_decEq(lean_object* v_x_1_, lean_object* v_x_2_){
_start:
{
lean_object* v_player_3_; lean_object* v_seq_4_; lean_object* v_action_5_; uint8_t v_isAuto_6_; lean_object* v_player_7_; lean_object* v_seq_8_; lean_object* v_action_9_; uint8_t v_isAuto_10_; uint8_t v___x_11_; 
v_player_3_ = lean_ctor_get(v_x_1_, 0);
v_seq_4_ = lean_ctor_get(v_x_1_, 1);
v_action_5_ = lean_ctor_get(v_x_1_, 2);
v_isAuto_6_ = lean_ctor_get_uint8(v_x_1_, sizeof(void*)*3);
v_player_7_ = lean_ctor_get(v_x_2_, 0);
v_seq_8_ = lean_ctor_get(v_x_2_, 1);
v_action_9_ = lean_ctor_get(v_x_2_, 2);
v_isAuto_10_ = lean_ctor_get_uint8(v_x_2_, sizeof(void*)*3);
v___x_11_ = lean_nat_dec_eq(v_player_3_, v_player_7_);
if (v___x_11_ == 0)
{
return v___x_11_;
}
else
{
uint8_t v___x_12_; 
v___x_12_ = lean_nat_dec_eq(v_seq_4_, v_seq_8_);
if (v___x_12_ == 0)
{
return v___x_12_;
}
else
{
uint8_t v___x_13_; 
v___x_13_ = lean_nat_dec_eq(v_action_5_, v_action_9_);
if (v___x_13_ == 0)
{
return v___x_13_;
}
else
{
if (v_isAuto_6_ == 0)
{
if (v_isAuto_10_ == 0)
{
return v___x_13_;
}
else
{
return v_isAuto_6_;
}
}
else
{
return v_isAuto_10_;
}
}
}
}
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_instDecidableEqLogEntry_decEq___boxed(lean_object* v_x_14_, lean_object* v_x_15_){
_start:
{
uint8_t v_res_16_; lean_object* v_r_17_; 
v_res_16_ = lp_airs__lean_AirsLean_instDecidableEqLogEntry_decEq(v_x_14_, v_x_15_);
lean_dec_ref(v_x_15_);
lean_dec_ref(v_x_14_);
v_r_17_ = lean_box(v_res_16_);
return v_r_17_;
}
}
LEAN_EXPORT uint8_t lp_airs__lean_AirsLean_instDecidableEqLogEntry(lean_object* v_x_18_, lean_object* v_x_19_){
_start:
{
uint8_t v___x_20_; 
v___x_20_ = lp_airs__lean_AirsLean_instDecidableEqLogEntry_decEq(v_x_18_, v_x_19_);
return v___x_20_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_instDecidableEqLogEntry___boxed(lean_object* v_x_21_, lean_object* v_x_22_){
_start:
{
uint8_t v_res_23_; lean_object* v_r_24_; 
v_res_23_ = lp_airs__lean_AirsLean_instDecidableEqLogEntry(v_x_21_, v_x_22_);
lean_dec_ref(v_x_22_);
lean_dec_ref(v_x_21_);
v_r_24_ = lean_box(v_res_23_);
return v_r_24_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_List_filterTR_loop___at___00AirsLean_playerSeqs_spec__0(lean_object* v_p_25_, lean_object* v_a_26_, lean_object* v_a_27_){
_start:
{
if (lean_obj_tag(v_a_26_) == 0)
{
lean_object* v___x_28_; 
v___x_28_ = l_List_reverse___redArg(v_a_27_);
return v___x_28_;
}
else
{
lean_object* v_head_29_; lean_object* v_tail_30_; lean_object* v___x_32_; uint8_t v_isShared_33_; uint8_t v_isSharedCheck_41_; 
v_head_29_ = lean_ctor_get(v_a_26_, 0);
v_tail_30_ = lean_ctor_get(v_a_26_, 1);
v_isSharedCheck_41_ = !lean_is_exclusive(v_a_26_);
if (v_isSharedCheck_41_ == 0)
{
v___x_32_ = v_a_26_;
v_isShared_33_ = v_isSharedCheck_41_;
goto v_resetjp_31_;
}
else
{
lean_inc(v_tail_30_);
lean_inc(v_head_29_);
lean_dec(v_a_26_);
v___x_32_ = lean_box(0);
v_isShared_33_ = v_isSharedCheck_41_;
goto v_resetjp_31_;
}
v_resetjp_31_:
{
lean_object* v_player_34_; uint8_t v___x_35_; 
v_player_34_ = lean_ctor_get(v_head_29_, 0);
v___x_35_ = lean_nat_dec_eq(v_player_34_, v_p_25_);
if (v___x_35_ == 0)
{
lean_del_object(v___x_32_);
lean_dec(v_head_29_);
v_a_26_ = v_tail_30_;
goto _start;
}
else
{
lean_object* v___x_38_; 
if (v_isShared_33_ == 0)
{
lean_ctor_set(v___x_32_, 1, v_a_27_);
v___x_38_ = v___x_32_;
goto v_reusejp_37_;
}
else
{
lean_object* v_reuseFailAlloc_40_; 
v_reuseFailAlloc_40_ = lean_alloc_ctor(1, 2, 0);
lean_ctor_set(v_reuseFailAlloc_40_, 0, v_head_29_);
lean_ctor_set(v_reuseFailAlloc_40_, 1, v_a_27_);
v___x_38_ = v_reuseFailAlloc_40_;
goto v_reusejp_37_;
}
v_reusejp_37_:
{
v_a_26_ = v_tail_30_;
v_a_27_ = v___x_38_;
goto _start;
}
}
}
}
}
}
LEAN_EXPORT lean_object* lp_airs__lean_List_filterTR_loop___at___00AirsLean_playerSeqs_spec__0___boxed(lean_object* v_p_42_, lean_object* v_a_43_, lean_object* v_a_44_){
_start:
{
lean_object* v_res_45_; 
v_res_45_ = lp_airs__lean_List_filterTR_loop___at___00AirsLean_playerSeqs_spec__0(v_p_42_, v_a_43_, v_a_44_);
lean_dec(v_p_42_);
return v_res_45_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_List_mapTR_loop___at___00AirsLean_playerSeqs_spec__1(lean_object* v_a_46_, lean_object* v_a_47_){
_start:
{
if (lean_obj_tag(v_a_46_) == 0)
{
lean_object* v___x_48_; 
v___x_48_ = l_List_reverse___redArg(v_a_47_);
return v___x_48_;
}
else
{
lean_object* v_head_49_; lean_object* v_tail_50_; lean_object* v___x_52_; uint8_t v_isShared_53_; uint8_t v_isSharedCheck_59_; 
v_head_49_ = lean_ctor_get(v_a_46_, 0);
v_tail_50_ = lean_ctor_get(v_a_46_, 1);
v_isSharedCheck_59_ = !lean_is_exclusive(v_a_46_);
if (v_isSharedCheck_59_ == 0)
{
v___x_52_ = v_a_46_;
v_isShared_53_ = v_isSharedCheck_59_;
goto v_resetjp_51_;
}
else
{
lean_inc(v_tail_50_);
lean_inc(v_head_49_);
lean_dec(v_a_46_);
v___x_52_ = lean_box(0);
v_isShared_53_ = v_isSharedCheck_59_;
goto v_resetjp_51_;
}
v_resetjp_51_:
{
lean_object* v_seq_54_; lean_object* v___x_56_; 
v_seq_54_ = lean_ctor_get(v_head_49_, 1);
lean_inc(v_seq_54_);
lean_dec(v_head_49_);
if (v_isShared_53_ == 0)
{
lean_ctor_set(v___x_52_, 1, v_a_47_);
lean_ctor_set(v___x_52_, 0, v_seq_54_);
v___x_56_ = v___x_52_;
goto v_reusejp_55_;
}
else
{
lean_object* v_reuseFailAlloc_58_; 
v_reuseFailAlloc_58_ = lean_alloc_ctor(1, 2, 0);
lean_ctor_set(v_reuseFailAlloc_58_, 0, v_seq_54_);
lean_ctor_set(v_reuseFailAlloc_58_, 1, v_a_47_);
v___x_56_ = v_reuseFailAlloc_58_;
goto v_reusejp_55_;
}
v_reusejp_55_:
{
v_a_46_ = v_tail_50_;
v_a_47_ = v___x_56_;
goto _start;
}
}
}
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_playerSeqs(lean_object* v_log_60_, lean_object* v_p_61_){
_start:
{
lean_object* v___x_62_; lean_object* v___x_63_; lean_object* v___x_64_; 
v___x_62_ = lean_box(0);
v___x_63_ = lp_airs__lean_List_filterTR_loop___at___00AirsLean_playerSeqs_spec__0(v_p_61_, v_log_60_, v___x_62_);
v___x_64_ = lp_airs__lean_List_mapTR_loop___at___00AirsLean_playerSeqs_spec__1(v___x_63_, v___x_62_);
return v___x_64_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_playerSeqs___boxed(lean_object* v_log_65_, lean_object* v_p_66_){
_start:
{
lean_object* v_res_67_; 
v_res_67_ = lp_airs__lean_AirsLean_playerSeqs(v_log_65_, v_p_66_);
lean_dec(v_p_66_);
return v_res_67_;
}
}
lean_object* initialize_Init(uint8_t builtin);
lean_object* initialize_Init(uint8_t builtin);
lean_object* initialize_airs__lean_AirsLean_Censorship_ActionSig(uint8_t builtin);
static bool _G_initialized = false;
LEAN_EXPORT lean_object* initialize_airs__lean_AirsLean_Censorship_ActionLog(uint8_t builtin) {
lean_object * res;
if (_G_initialized) return lean_io_result_mk_ok(lean_box(0));
_G_initialized = true;
res = initialize_Init(builtin);
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_Init(builtin);
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_airs__lean_AirsLean_Censorship_ActionSig(builtin);
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
return lean_io_result_mk_ok(lean_box(0));
}
#ifdef __cplusplus
}
#endif
