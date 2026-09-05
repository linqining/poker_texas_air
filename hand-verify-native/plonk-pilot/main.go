// plonk-pilot — Stark 曲线 EC 的 PLONK 电路试点（gnark, BLS12-381 后端）。
//
// 电路域 = BLS12-381 标量域；Stark 曲线域/群运算通过 gnark emulated
// arithmetic（官方 STARKCurveFp/Fr 参数 + GetStarkCurveParams）仿真。
//
// 三个电路：
//   mul     — emulated felt252 模乘断言：r = a·b mod P（N 条并行）
//   scalar  — emulated Stark 曲线标量乘：Q = s·G（base point）
//   tamper  — 负例：错误的 Q 不可证
//
// 注意：plonk.Setup 使用 gnark 测试 SRS（非生产仪式），仅用于性能度量。
package main

import (
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	stark_curve "github.com/consensys/gnark-crypto/ecc/stark-curve"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	scs "github.com/consensys/gnark/frontend/cs/scs"
	unsafekzg "github.com/consensys/gnark/test/unsafekzg"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// ---- Stark 域/群参数（gnark 官方 emparams）----

type StarkBase = emulated.STARKCurveFp  // felt252 仿真参数
type StarkScalar = emulated.STARKCurveFr // Stark 曲线阶（仿真参数）

// ---- 电路 1：N 条并行 emulated 模乘 ----

type MulCircuit struct {
	A []emulated.Element[StarkBase] `gnark:",secret"`
	B []emulated.Element[StarkBase] `gnark:",secret"`
	R []emulated.Element[StarkBase] `gnark:",secret"`
}

func (c *MulCircuit) Define(api frontend.API) error {
	f, err := emulated.NewField[StarkBase](api)
	if err != nil {
		return err
	}
	for i := range c.A {
		prod := f.Mul(&c.A[i], &c.B[i])
		f.AssertIsEqual(prod, &c.R[i])
	}
	return nil
}

// ---- 电路 2：emulated Stark 曲线标量乘 Q = s·G ----

type ScalarMulCircuit struct {
	S  emulated.Element[StarkScalar]    `gnark:",secret"`
	QX emulated.Element[StarkBase]      `gnark:",secret"`
	QY emulated.Element[StarkBase]      `gnark:",secret"`
}

func (c *ScalarMulCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[StarkBase, StarkScalar](api, sw_emulated.GetStarkCurveParams())
	if err != nil {
		return err
	}
	f, err := emulated.NewField[StarkBase](api)
	if err != nil {
		return err
	}
	_, g1 := stark_curve.Generators()
	g := sw_emulated.AffinePoint[StarkBase]{
		X: emulated.ValueOf[StarkBase](g1.X.BigInt(new(big.Int))),
		Y: emulated.ValueOf[StarkBase](g1.Y.BigInt(new(big.Int))),
	}
	s := &c.S
	q := curve.ScalarMul(&g, s)
	f.AssertIsEqual(&q.X, &c.QX)
	f.AssertIsEqual(&q.Y, &c.QY)
	return nil
}

// ---- helpers ----

func compileAndMeasure(name string, circuit frontend.Circuit, assignment frontend.Circuit) {
	t0 := time.Now()
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, circuit)
	if err != nil {
		fmt.Printf("%s: compile error: %v\n", name, err)
		os.Exit(1)
	}
	compileMs := time.Since(t0).Milliseconds()
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		fmt.Printf("%s: srs error: %v\n", name, err)
		os.Exit(1)
	}
	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		fmt.Printf("%s: setup error: %v\n", name, err)
		os.Exit(1)
	}
	witnessFull, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		fmt.Printf("%s: witness error: %v\n", name, err)
		os.Exit(1)
	}
	publicWitness, err := witnessFull.Public()
	if err != nil {
		fmt.Printf("%s: public witness error: %v\n", name, err)
		os.Exit(1)
	}
	t0 = time.Now()
	proof, err := plonk.Prove(ccs, pk, witnessFull)
	if err != nil {
		fmt.Printf("%s: prove error: %v\n", name, err)
		os.Exit(1)
	}
	proveMs := time.Since(t0).Milliseconds()
	t0 = time.Now()
	err = plonk.Verify(proof, vk, publicWitness)
	verifyMs := time.Since(t0).Milliseconds()
	fmt.Printf(
		"[%s] constraints=%d compile=%dms prove=%dms verify=%dms ok=%v\n",
		name, ccs.GetNbConstraints(), compileMs, proveMs, verifyMs, err == nil,
	)
}

func runMul(n int) {
	cir := &MulCircuit{
		A: make([]emulated.Element[StarkBase], n),
		B: make([]emulated.Element[StarkBase], n),
		R: make([]emulated.Element[StarkBase], n),
	}
	asg := &MulCircuit{
		A: make([]emulated.Element[StarkBase], n),
		B: make([]emulated.Element[StarkBase], n),
		R: make([]emulated.Element[StarkBase], n),
	}
	for i := 0; i < n; i++ {
		a := bn(fmt.Sprintf("%d", 1000003+i))
		b := bn(fmt.Sprintf("%d", 999999937+i))
		r := new(big.Int).Mod(new(big.Int).Mul(a, b), modulusP())
		asg.A[i] = emulated.ValueOf[StarkBase](a)
		asg.B[i] = emulated.ValueOf[StarkBase](b)
		asg.R[i] = emulated.ValueOf[StarkBase](r)
	}
	compileAndMeasure(fmt.Sprintf("mul x%d", n), cir, asg)
}


func bn(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("bad decimal")
	}
	return v
}

func main() {
	mode := "all"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch mode {
	case "mul":
		runMul(1)
	case "mulbench":
		for _, n := range []int{1, 8, 64} {
			runMul(n)
		}
	case "scalar":
		scalarMode()
	case "tamper":
		tamperMode()
	case "all":
		runMul(1)
		runMul(8)
		runMul(64)
		scalarMode()
		tamperMode()
	default:
		fmt.Printf("unknown mode %q\n", mode)
		os.Exit(2)
	}
}

func scalarMode() {
	s := bn("1234567890123456789012345678901234567890123456789012345678901234567890")
	_, g1 := stark_curve.Generators()
	var q stark_curve.G1Affine
	q.ScalarMultiplication(&g1, s)
	cir := &ScalarMulCircuit{}
	asg := &ScalarMulCircuit{
		S:  emulated.ValueOf[StarkScalar](s),
		QX: emulated.ValueOf[StarkBase](q.X.BigInt(new(big.Int))),
		QY: emulated.ValueOf[StarkBase](q.Y.BigInt(new(big.Int))),
	}
	compileAndMeasure("scalar-mul x1", cir, asg)
}

func tamperMode() {
	s := bn("1234567890123456789012345678901234567890123456789012345678901234567890")
	_, g1 := stark_curve.Generators()
	var q stark_curve.G1Affine
	q.ScalarMultiplication(&g1, s)
	wrongX := new(big.Int).Add(q.X.BigInt(new(big.Int)), big.NewInt(1))
	cir := &ScalarMulCircuit{}
	asg := &ScalarMulCircuit{
		S:  emulated.ValueOf[StarkScalar](s),
		QX: emulated.ValueOf[StarkBase](wrongX),
		QY: emulated.ValueOf[StarkBase](q.Y.BigInt(new(big.Int))),
	}
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, cir)
	if err != nil {
		panic(err)
	}
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		panic(err)
	}
	pk, _, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		panic(err)
	}
	witnessFull, err := frontend.NewWitness(asg, ecc.BLS12_381.ScalarField())
	if err != nil {
		panic(err)
	}
	_, err = plonk.Prove(ccs, pk, witnessFull)
	fmt.Printf("[tamper] wrong Q prove rejected: %v\n", err != nil)
}

func modulusP() *big.Int {
	// Stark 曲线基域 P = 2^251 + 17·2^192 + 1
	p, _ := new(big.Int).SetString("8000000000000011000000000000000000000000000000000000000000000001", 16)
	return p
}
