package galois


func GalAdd(a, b byte) byte {
	return a ^ b
}

func GalSub(a, b byte) byte {
	return a ^ b
}

// GalMultiply multiplies two elements a and b in GF(2^8)
// with precomputed lookup table for faster performance.
// Use GalMultiplyLogExp to do the same operation with less
// memory.
func GalMultiply(a, b byte) byte {
	return mulTable[a][b]
}

// GalMultiplyLogExp multiplies two elements a and b in GF(2^8)
// using log and exp tables.
func GalMultiplyLogExp(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	logA := int(logTable[a])
	logB := int(logTable[b])
	return expTable[logA+logB]
}

// GalDivide is the inverse of GalMultiply, dividing element a by b
// in GF(2^8).
func GalDivide(a, b byte) byte {
	if a == 0 {
		return 0
	}
	if b == 0 {
		panic("Argument 'divisor' is 0")
	}
	logA := int(logTable[a])
	logB := int(logTable[b])
	logResult := logA - logB
	if logResult < 0 {
		logResult += 255
	}
	return expTable[logResult]
}

// GalExp computes a**n.
// The result will be the same as multiplying a times itself n times.
func GalExp(a byte, n int) byte {
	if n == 0 {
		return 1
	}
	if a == 0 {
		return 0
	}

	logA := logTable[a]
	logResult := int(logA) * n
	for logResult >= 255 {
		logResult -= 255
	}
	return expTable[logResult]
}

//func genAvx2Matrix(matrixRows [][]byte, inputs, outputs int, dst []byte) []byte {
//	if !avx2CodeGen {
//		panic("codegen not enabled")
//	}
//	total := inputs * outputs
//
//	// Duplicated in+out
//	wantBytes := total * 32 * 2
//	if cap(dst) < wantBytes {
//		dst = make([]byte, wantBytes)
//	} else {
//		dst = dst[:wantBytes]
//	}
//	for i, row := range matrixRows[:outputs] {
//		for j, idx := range row[:inputs] {
//			dstIdx := (j*outputs + i) * 64
//			dstPart := dst[dstIdx:]
//			dstPart = dstPart[:64]
//			lo := mulTableLow[idx][:]
//			hi := mulTableHigh[idx][:]
//			copy(dstPart[:16], lo)
//			copy(dstPart[16:32], lo)
//			copy(dstPart[32:48], hi)
//			copy(dstPart[48:64], hi)
//		}
//	}
//	return dst
//}