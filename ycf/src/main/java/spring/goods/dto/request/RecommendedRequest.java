package spring.goods.dto.request;

import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

@Data
public class RecommendedRequest extends PegeBeanUtile{
    @ApiModelProperty(value = "商品分类ID")
    private Long pmsType;

    @ApiModelProperty(value = "商品名")
    private Long goodsName;

    @ApiModelProperty(value = "上新:0->上新")
    private Integer goodDesc;

    @ApiModelProperty(value = "排序：降序goods_price DESC,goods_price ASC升序")
    private String orderByClause;

}
