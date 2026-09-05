// Lean compiler output
// Module: AirsLean.Custody.Conservation
// Imports: public import Init public meta import Init public import AirsLean.Custody.ChipState
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
lean_object* lean_nat_add(lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_Step_ctorIdx(lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_Step_ctorIdx___boxed(lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_Step_ctorElim___redArg(lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_Step_ctorElim(lean_object*, lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_Step_ctorElim___boxed(lean_object*, lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_Step_idle_elim___redArg(lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_Step_idle_elim(lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_Step_funding_elim___redArg(lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_Step_funding_elim(lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_Step_payout_elim___redArg(lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_Step_payout_elim(lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_totalDeposit(lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_totalDeposit___boxed(lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_totalPayout(lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_totalPayout___boxed(lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean___private_AirsLean_Custody_Conservation_0__AirsLean_totalPayout_match__1_splitter___redArg(lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean___private_AirsLean_Custody_Conservation_0__AirsLean_totalPayout_match__1_splitter(lean_object*, lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean___private_AirsLean_Custody_Conservation_0__AirsLean_totalDeposit_match__1_splitter___redArg(lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean___private_AirsLean_Custody_Conservation_0__AirsLean_totalDeposit_match__1_splitter(lean_object*, lean_object*, lean_object*, lean_object*, lean_object*);
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_Step_ctorIdx(lean_object* v_x_1_){
_start:
{
switch(lean_obj_tag(v_x_1_))
{
case 0:
{
lean_object* v___x_2_; 
v___x_2_ = lean_unsigned_to_nat(0u);
return v___x_2_;
}
case 1:
{
lean_object* v___x_3_; 
v___x_3_ = lean_unsigned_to_nat(1u);
return v___x_3_;
}
default: 
{
lean_object* v___x_4_; 
v___x_4_ = lean_unsigned_to_nat(2u);
return v___x_4_;
}
}
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_Step_ctorIdx___boxed(lean_object* v_x_5_){
_start:
{
lean_object* v_res_6_; 
v_res_6_ = lp_airs__lean_AirsLean_Step_ctorIdx(v_x_5_);
lean_dec(v_x_5_);
return v_res_6_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_Step_ctorElim___redArg(lean_object* v_t_7_, lean_object* v_k_8_){
_start:
{
if (lean_obj_tag(v_t_7_) == 0)
{
return v_k_8_;
}
else
{
lean_object* v_a_9_; lean_object* v___x_10_; 
v_a_9_ = lean_ctor_get(v_t_7_, 0);
lean_inc(v_a_9_);
lean_dec(v_t_7_);
v___x_10_ = lean_apply_1(v_k_8_, v_a_9_);
return v___x_10_;
}
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_Step_ctorElim(lean_object* v_motive_11_, lean_object* v_ctorIdx_12_, lean_object* v_t_13_, lean_object* v_h_14_, lean_object* v_k_15_){
_start:
{
lean_object* v___x_16_; 
v___x_16_ = lp_airs__lean_AirsLean_Step_ctorElim___redArg(v_t_13_, v_k_15_);
return v___x_16_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_Step_ctorElim___boxed(lean_object* v_motive_17_, lean_object* v_ctorIdx_18_, lean_object* v_t_19_, lean_object* v_h_20_, lean_object* v_k_21_){
_start:
{
lean_object* v_res_22_; 
v_res_22_ = lp_airs__lean_AirsLean_Step_ctorElim(v_motive_17_, v_ctorIdx_18_, v_t_19_, v_h_20_, v_k_21_);
lean_dec(v_ctorIdx_18_);
return v_res_22_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_Step_idle_elim___redArg(lean_object* v_t_23_, lean_object* v_idle_24_){
_start:
{
lean_object* v___x_25_; 
v___x_25_ = lp_airs__lean_AirsLean_Step_ctorElim___redArg(v_t_23_, v_idle_24_);
return v___x_25_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_Step_idle_elim(lean_object* v_motive_26_, lean_object* v_t_27_, lean_object* v_h_28_, lean_object* v_idle_29_){
_start:
{
lean_object* v___x_30_; 
v___x_30_ = lp_airs__lean_AirsLean_Step_ctorElim___redArg(v_t_27_, v_idle_29_);
return v___x_30_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_Step_funding_elim___redArg(lean_object* v_t_31_, lean_object* v_funding_32_){
_start:
{
lean_object* v___x_33_; 
v___x_33_ = lp_airs__lean_AirsLean_Step_ctorElim___redArg(v_t_31_, v_funding_32_);
return v___x_33_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_Step_funding_elim(lean_object* v_motive_34_, lean_object* v_t_35_, lean_object* v_h_36_, lean_object* v_funding_37_){
_start:
{
lean_object* v___x_38_; 
v___x_38_ = lp_airs__lean_AirsLean_Step_ctorElim___redArg(v_t_35_, v_funding_37_);
return v___x_38_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_Step_payout_elim___redArg(lean_object* v_t_39_, lean_object* v_payout_40_){
_start:
{
lean_object* v___x_41_; 
v___x_41_ = lp_airs__lean_AirsLean_Step_ctorElim___redArg(v_t_39_, v_payout_40_);
return v___x_41_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_Step_payout_elim(lean_object* v_motive_42_, lean_object* v_t_43_, lean_object* v_h_44_, lean_object* v_payout_45_){
_start:
{
lean_object* v___x_46_; 
v___x_46_ = lp_airs__lean_AirsLean_Step_ctorElim___redArg(v_t_43_, v_payout_45_);
return v___x_46_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_totalDeposit(lean_object* v_steps_47_){
_start:
{
if (lean_obj_tag(v_steps_47_) == 0)
{
lean_object* v___x_48_; 
v___x_48_ = lean_unsigned_to_nat(0u);
return v___x_48_;
}
else
{
lean_object* v_head_49_; 
v_head_49_ = lean_ctor_get(v_steps_47_, 0);
if (lean_obj_tag(v_head_49_) == 1)
{
lean_object* v_tail_50_; lean_object* v_a_51_; lean_object* v___x_52_; lean_object* v___x_53_; 
v_tail_50_ = lean_ctor_get(v_steps_47_, 1);
v_a_51_ = lean_ctor_get(v_head_49_, 0);
v___x_52_ = lp_airs__lean_AirsLean_totalDeposit(v_tail_50_);
v___x_53_ = lean_nat_add(v_a_51_, v___x_52_);
lean_dec(v___x_52_);
return v___x_53_;
}
else
{
lean_object* v_tail_54_; 
v_tail_54_ = lean_ctor_get(v_steps_47_, 1);
v_steps_47_ = v_tail_54_;
goto _start;
}
}
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_totalDeposit___boxed(lean_object* v_steps_56_){
_start:
{
lean_object* v_res_57_; 
v_res_57_ = lp_airs__lean_AirsLean_totalDeposit(v_steps_56_);
lean_dec(v_steps_56_);
return v_res_57_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_totalPayout(lean_object* v_steps_58_){
_start:
{
if (lean_obj_tag(v_steps_58_) == 0)
{
lean_object* v___x_59_; 
v___x_59_ = lean_unsigned_to_nat(0u);
return v___x_59_;
}
else
{
lean_object* v_head_60_; 
v_head_60_ = lean_ctor_get(v_steps_58_, 0);
if (lean_obj_tag(v_head_60_) == 2)
{
lean_object* v_tail_61_; lean_object* v_a_62_; lean_object* v___x_63_; lean_object* v___x_64_; 
v_tail_61_ = lean_ctor_get(v_steps_58_, 1);
v_a_62_ = lean_ctor_get(v_head_60_, 0);
v___x_63_ = lp_airs__lean_AirsLean_totalPayout(v_tail_61_);
v___x_64_ = lean_nat_add(v_a_62_, v___x_63_);
lean_dec(v___x_63_);
return v___x_64_;
}
else
{
lean_object* v_tail_65_; 
v_tail_65_ = lean_ctor_get(v_steps_58_, 1);
v_steps_58_ = v_tail_65_;
goto _start;
}
}
}
}
LEAN_EXPORT lean_object* lp_airs__lean_AirsLean_totalPayout___boxed(lean_object* v_steps_67_){
_start:
{
lean_object* v_res_68_; 
v_res_68_ = lp_airs__lean_AirsLean_totalPayout(v_steps_67_);
lean_dec(v_steps_67_);
return v_res_68_;
}
}
LEAN_EXPORT lean_object* lp_airs__lean___private_AirsLean_Custody_Conservation_0__AirsLean_totalPayout_match__1_splitter___redArg(lean_object* v_steps_69_, lean_object* v_h__1_70_, lean_object* v_h__2_71_, lean_object* v_h__3_72_){
_start:
{
if (lean_obj_tag(v_steps_69_) == 0)
{
lean_object* v___x_73_; lean_object* v___x_74_; 
lean_dec(v_h__3_72_);
lean_dec(v_h__2_71_);
v___x_73_ = lean_box(0);
v___x_74_ = lean_apply_1(v_h__1_70_, v___x_73_);
return v___x_74_;
}
else
{
lean_object* v_head_75_; 
lean_dec(v_h__1_70_);
v_head_75_ = lean_ctor_get(v_steps_69_, 0);
lean_inc(v_head_75_);
if (lean_obj_tag(v_head_75_) == 2)
{
lean_object* v_tail_76_; lean_object* v_a_77_; lean_object* v___x_78_; 
lean_dec(v_h__3_72_);
v_tail_76_ = lean_ctor_get(v_steps_69_, 1);
lean_inc(v_tail_76_);
lean_dec_ref_known(v_steps_69_, 2);
v_a_77_ = lean_ctor_get(v_head_75_, 0);
lean_inc(v_a_77_);
lean_dec_ref_known(v_head_75_, 1);
v___x_78_ = lean_apply_2(v_h__2_71_, v_a_77_, v_tail_76_);
return v___x_78_;
}
else
{
lean_object* v_tail_79_; lean_object* v___x_80_; 
lean_dec(v_h__2_71_);
v_tail_79_ = lean_ctor_get(v_steps_69_, 1);
lean_inc(v_tail_79_);
lean_dec_ref_known(v_steps_69_, 2);
v___x_80_ = lean_apply_3(v_h__3_72_, v_head_75_, v_tail_79_, lean_box(0));
return v___x_80_;
}
}
}
}
LEAN_EXPORT lean_object* lp_airs__lean___private_AirsLean_Custody_Conservation_0__AirsLean_totalPayout_match__1_splitter(lean_object* v_motive_81_, lean_object* v_steps_82_, lean_object* v_h__1_83_, lean_object* v_h__2_84_, lean_object* v_h__3_85_){
_start:
{
if (lean_obj_tag(v_steps_82_) == 0)
{
lean_object* v___x_86_; lean_object* v___x_87_; 
lean_dec(v_h__3_85_);
lean_dec(v_h__2_84_);
v___x_86_ = lean_box(0);
v___x_87_ = lean_apply_1(v_h__1_83_, v___x_86_);
return v___x_87_;
}
else
{
lean_object* v_head_88_; 
lean_dec(v_h__1_83_);
v_head_88_ = lean_ctor_get(v_steps_82_, 0);
lean_inc(v_head_88_);
if (lean_obj_tag(v_head_88_) == 2)
{
lean_object* v_tail_89_; lean_object* v_a_90_; lean_object* v___x_91_; 
lean_dec(v_h__3_85_);
v_tail_89_ = lean_ctor_get(v_steps_82_, 1);
lean_inc(v_tail_89_);
lean_dec_ref_known(v_steps_82_, 2);
v_a_90_ = lean_ctor_get(v_head_88_, 0);
lean_inc(v_a_90_);
lean_dec_ref_known(v_head_88_, 1);
v___x_91_ = lean_apply_2(v_h__2_84_, v_a_90_, v_tail_89_);
return v___x_91_;
}
else
{
lean_object* v_tail_92_; lean_object* v___x_93_; 
lean_dec(v_h__2_84_);
v_tail_92_ = lean_ctor_get(v_steps_82_, 1);
lean_inc(v_tail_92_);
lean_dec_ref_known(v_steps_82_, 2);
v___x_93_ = lean_apply_3(v_h__3_85_, v_head_88_, v_tail_92_, lean_box(0));
return v___x_93_;
}
}
}
}
LEAN_EXPORT lean_object* lp_airs__lean___private_AirsLean_Custody_Conservation_0__AirsLean_totalDeposit_match__1_splitter___redArg(lean_object* v_steps_94_, lean_object* v_h__1_95_, lean_object* v_h__2_96_, lean_object* v_h__3_97_){
_start:
{
if (lean_obj_tag(v_steps_94_) == 0)
{
lean_object* v___x_98_; lean_object* v___x_99_; 
lean_dec(v_h__3_97_);
lean_dec(v_h__2_96_);
v___x_98_ = lean_box(0);
v___x_99_ = lean_apply_1(v_h__1_95_, v___x_98_);
return v___x_99_;
}
else
{
lean_object* v_head_100_; 
lean_dec(v_h__1_95_);
v_head_100_ = lean_ctor_get(v_steps_94_, 0);
lean_inc(v_head_100_);
if (lean_obj_tag(v_head_100_) == 1)
{
lean_object* v_tail_101_; lean_object* v_a_102_; lean_object* v___x_103_; 
lean_dec(v_h__3_97_);
v_tail_101_ = lean_ctor_get(v_steps_94_, 1);
lean_inc(v_tail_101_);
lean_dec_ref_known(v_steps_94_, 2);
v_a_102_ = lean_ctor_get(v_head_100_, 0);
lean_inc(v_a_102_);
lean_dec_ref_known(v_head_100_, 1);
v___x_103_ = lean_apply_2(v_h__2_96_, v_a_102_, v_tail_101_);
return v___x_103_;
}
else
{
lean_object* v_tail_104_; lean_object* v___x_105_; 
lean_dec(v_h__2_96_);
v_tail_104_ = lean_ctor_get(v_steps_94_, 1);
lean_inc(v_tail_104_);
lean_dec_ref_known(v_steps_94_, 2);
v___x_105_ = lean_apply_3(v_h__3_97_, v_head_100_, v_tail_104_, lean_box(0));
return v___x_105_;
}
}
}
}
LEAN_EXPORT lean_object* lp_airs__lean___private_AirsLean_Custody_Conservation_0__AirsLean_totalDeposit_match__1_splitter(lean_object* v_motive_106_, lean_object* v_steps_107_, lean_object* v_h__1_108_, lean_object* v_h__2_109_, lean_object* v_h__3_110_){
_start:
{
if (lean_obj_tag(v_steps_107_) == 0)
{
lean_object* v___x_111_; lean_object* v___x_112_; 
lean_dec(v_h__3_110_);
lean_dec(v_h__2_109_);
v___x_111_ = lean_box(0);
v___x_112_ = lean_apply_1(v_h__1_108_, v___x_111_);
return v___x_112_;
}
else
{
lean_object* v_head_113_; 
lean_dec(v_h__1_108_);
v_head_113_ = lean_ctor_get(v_steps_107_, 0);
lean_inc(v_head_113_);
if (lean_obj_tag(v_head_113_) == 1)
{
lean_object* v_tail_114_; lean_object* v_a_115_; lean_object* v___x_116_; 
lean_dec(v_h__3_110_);
v_tail_114_ = lean_ctor_get(v_steps_107_, 1);
lean_inc(v_tail_114_);
lean_dec_ref_known(v_steps_107_, 2);
v_a_115_ = lean_ctor_get(v_head_113_, 0);
lean_inc(v_a_115_);
lean_dec_ref_known(v_head_113_, 1);
v___x_116_ = lean_apply_2(v_h__2_109_, v_a_115_, v_tail_114_);
return v___x_116_;
}
else
{
lean_object* v_tail_117_; lean_object* v___x_118_; 
lean_dec(v_h__2_109_);
v_tail_117_ = lean_ctor_get(v_steps_107_, 1);
lean_inc(v_tail_117_);
lean_dec_ref_known(v_steps_107_, 2);
v___x_118_ = lean_apply_3(v_h__3_110_, v_head_113_, v_tail_117_, lean_box(0));
return v___x_118_;
}
}
}
}
lean_object* initialize_Init(uint8_t builtin);
lean_object* initialize_Init(uint8_t builtin);
lean_object* initialize_airs__lean_AirsLean_Custody_ChipState(uint8_t builtin);
static bool _G_initialized = false;
LEAN_EXPORT lean_object* initialize_airs__lean_AirsLean_Custody_Conservation(uint8_t builtin) {
lean_object * res;
if (_G_initialized) return lean_io_result_mk_ok(lean_box(0));
_G_initialized = true;
res = initialize_Init(builtin);
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_Init(builtin);
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_airs__lean_AirsLean_Custody_ChipState(builtin);
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
return lean_io_result_mk_ok(lean_box(0));
}
#ifdef __cplusplus
}
#endif
