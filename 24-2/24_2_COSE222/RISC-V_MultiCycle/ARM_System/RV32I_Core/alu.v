module ALU32bit(
	input[31:0] SrcA,
	input[31:0] SrcB,
	input[3:0] ALUOp,
	output reg[31:0] ALUResult,
	output reg[3:0] ALUFlags
	);
	
	always @ (*)
	begin
		case(ALUOp)
			4'b0010: // SUB operation
			begin
				ALUResult = SrcA - SrcB;
			end
			4'b0100: // ADD operation
			begin
				ALUResult = SrcA + SrcB;
			end
			4'b1010: // CMP operation
			begin
				ALUResult = SrcA - SrcB;
				if(SrcA == SrcB)
					ALUFlags = 4'bx1xx;
				else
					ALUFlags = 4'bx0xx;
			end
			4'b1101: // MOV operation
			begin
				ALUResult = SrcB;
			end
		endcase
	end
	
endmodule
		