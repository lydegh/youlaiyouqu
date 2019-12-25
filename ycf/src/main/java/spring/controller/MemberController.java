package spring.controller;

import io.swagger.annotations.ApiParam;
import org.springframework.validation.annotation.Validated;
import spring.annotation.CurrentUser;
import spring.annotation.LoginRequired;
import spring.dto.BaseCommonResult;
import spring.dto.request.*;
import spring.dto.result.*;
import spring.model.UUserMember;
import spring.service.MemberService;
import spring.model.UMemberReceiveAddress;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@Api(tags = "/memberCenter/members", description = "会员管理")
@RequestMapping("/memberCenter/members")
public class MemberController {
    @Autowired
    private MemberService userService;

    @ApiOperation(value = "登录")
    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public @ResponseBody BaseCommonResult<MemberLoginResponse>  login(@RequestBody MemberRequest record) {
        return userService.login(record);
    }
    @ApiOperation(value = "登出")
    @RequestMapping(value = "/logout/{code}", method = RequestMethod.GET)
    public @ResponseBody BaseCommonResult loginOut(@PathVariable String code) {
        return userService.loginOut(code);
    }


    @ApiOperation(value = "鱿费查询")
    @RequestMapping(value = "/money/{code}", method = RequestMethod.GET)
    @ResponseBody
    public BaseCommonResult getMoney(@PathVariable String code) {
        return userService.getMoney(code);
    }

    @ApiOperation(value = "会员收货地址添加", notes = "会员收货地址添加")
    @RequestMapping(value = "/add", method = RequestMethod.POST)
    @LoginRequired
    public BaseCommonResult add(@CurrentUser UUserMember user,@Validated @RequestBody UMemberReceiveAddress request){
        return userService.add(request);
    }


    @ApiOperation(value = "查看会员收货地址")
    @RequestMapping(value = "/address", method = RequestMethod.POST)
    public @ResponseBody BaseCommonResult getAddress(AddressRequest addressRequest) {
        return userService.getAddress(addressRequest);
    }

    @ApiOperation(value = "会员收货地址修改", notes = "会员收货地址修改")
    @RequestMapping(value = "/update", method = RequestMethod.POST)
    public @ResponseBody BaseCommonResult update(@Validated @RequestBody MemberReceiveAddressReq request){
        return userService.update(request);
    }


    @ApiOperation(value = "添加购物车", notes = "添加购物车")
    @RequestMapping(value = "/car/add", method = RequestMethod.POST)
    public BaseCommonResult addCar(@Validated @RequestBody MemberCarRequest request){
        return userService.addCar(request);
    }

    @ApiOperation(value = "删除购物车", notes = "删除购物车")
    @RequestMapping(value = "/car/delete", method = RequestMethod.POST)
    public BaseCommonResult deleteCar(@Validated @RequestBody MemberCarRequest request){
        return userService.deleteCar(request);
    }

    @ApiOperation(value = "查询购物车")
    @RequestMapping(value = "/car", method = RequestMethod.POST)
    public @ResponseBody BaseCommonResult<BasePage<MemberCarResult>>  memberCarList(@Validated @RequestBody MemberCarListRequest request) {
        return userService.memberCarList(request);
    }

    @ApiOperation(value = "用户绑定手机号")
    @RequestMapping(value = "/binding", method = RequestMethod.POST)
    public @ResponseBody BaseCommonResult binding(@Validated @RequestBody BinDingPhonRequest request) {
        return userService.binding(request);
    }

    @ApiOperation(value = "任务领取用户信息")
    @RequestMapping(value = "/login/{memberId}", method = RequestMethod.GET)
    public @ResponseBody BaseCommonResult<MemberPriceReslut>  getlogin(@PathVariable Long memberId) {
        return userService.getlogin(memberId);
    }

    @ApiOperation(value = "登录账号领取金币")
    @RequestMapping(value = "/jinbi/{memberId}/{type}", method = RequestMethod.GET)
    public @ResponseBody BaseCommonResult<UUserMember>  getjinbi(@PathVariable Long memberId, @ApiParam("1:关注公众号,2登录领取,3首次卖出,4首次购买,5鱿费获取") @PathVariable int type) {
        return userService.getjinbi(memberId,type);
    }

    @ApiOperation(value = "用户鱿费金币现金明细")
    @RequestMapping(value = "/member/{memberId}/{type}", method = RequestMethod.GET)
    public @ResponseBody BaseCommonResult<List<GetMemberResult>>  getmember(@PathVariable Long memberId, @ApiParam("1:鱿费,2金币,3现金") @PathVariable int type) {
        return userService.getmember(memberId,type);
    }
    @ApiOperation(value = "用户钱包")
    @RequestMapping(value = "/wallet/{memberId}", method = RequestMethod.GET)
    public @ResponseBody BaseCommonResult<MemberWalletResult>  getMemberWallet(@PathVariable Long memberId) {
        return userService.getMemberWallet(memberId);
    }

    @ApiOperation(value = "解锁金币")
    @RequestMapping(value = "/money/{memberId}/{type}", method = RequestMethod.GET)
    @ResponseBody
    public BaseCommonResult getMoney(@PathVariable Long memberId,@ApiParam("1:解锁10元,2解锁30元,3解锁50元,4解锁100元")@PathVariable int type) {
        return userService.getMoney(memberId,type);
    }
}
