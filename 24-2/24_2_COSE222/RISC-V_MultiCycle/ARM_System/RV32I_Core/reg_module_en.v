module reg_module_en #(parameter WIDTH = 8)(
input clk,
input rst,
input en,
input [WIDTH-1:0] d,
output reg [WIDTH-1:0] q
);

always@(posedge clk) begin
	if(!rst)
		q <= 0;
	else if(en) 
        q <= d;
end

endmodule