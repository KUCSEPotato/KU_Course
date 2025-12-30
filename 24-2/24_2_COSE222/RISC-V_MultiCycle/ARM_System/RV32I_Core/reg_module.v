module reg_module #(parameter WIDTH = 8)(
input clk,
input rst,
input [WIDTH-1:0] d,
output reg [WIDTH-1:0] q
);

always@(posedge clk) begin
	if(!rst)
		q <= 0;
	else
		q <= d;
end

endmodule