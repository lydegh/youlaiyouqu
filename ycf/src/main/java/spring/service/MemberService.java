package spring.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.github.pagehelper.PageHelper;
import com.github.pagehelper.PageInfo;
import org.apache.commons.lang3.StringUtils;
import org.springframework.data.annotation.Transient;
import spring.dto.BaseCommonResult;
import spring.dto.request.*;
import spring.dto.result.*;
import spring.exception.GoodsException;
import spring.mapper.*;
import spring.mapper.cvs.MemberCarMapper;
import spring.mapper.cvs.MemberOrderMapper;
import spring.mapper.cvs.TradeAdminMapper;
import spring.model.*;
import spring.utils.Constants;
import spring.utils.ResultBuilder;
import spring.utils.TonKenUtile;
import lombok.extern.slf4j.Slf4j;
import org.dozer.DozerBeanMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import spring.utils.UserInfoRedisUtil;
import spring.wechat.service.WechatService;

import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@Service
public class MemberService {
    @Autowired
    private UUserMemberMapper userMemberMapper;
    @Autowired
    private UMemberReceiveAddressMapper memberReceiveAddressMapper;
    @Autowired
    private DozerBeanMapper dozerMapper;
    @Autowired
    private MMemberCarMapper mMemberCarMapper;
    @Autowired
    private MMemberCarDetailMapper mMemberCarDetailMapper;
    @Autowired
    private MemberCarMapper memberCarMapper;
    @Autowired
    private WechatService wechatService;
    @Autowired
    private POrdersMapper ordersMapper;
    @Autowired
    private MRecoveryGoodsMapper recoveryGoodsMapper;
    @Autowired
    private TradeAdminMapper tradeAdminMapper;
    @Autowired
    private MemberOrderMapper memberOrderMapper;
    @Autowired
    private MMemberJbMapper memberJbMapper;

    @Transient
    public BaseCommonResult<UUserMember> register(MemberRequest record) {
        log.info("会员注册请求参数:{}",record);
        UUserMember map = dozerMapper.map(record, UUserMember.class);
        map.setCreateTime(new Date());
        UUserMemberExample example = new UUserMemberExample();
        example.createCriteria().andAppIdEqualTo(record.getAppId());
        List<UUserMember> uUserMembers = userMemberMapper.selectByExample(example);
        if (uUserMembers.size()>0){
            return ResultBuilder.fail("用户已注册");
        }
        int i = userMemberMapper.insertSelective(map);
        log.info("会员注册注册成功:{}",map);
        return ResultBuilder.success(map);
    }

    public String getToken(UserLoginResponse result, UserLoginDto loginDto, MUserManual member,UUserMember userMember) {
        String loginId = member.getWfcode();
        String channelId = loginDto.getChannelId();
        String userType = loginDto.getUserType();
        String token = "";
        try {
            token = JWT.create()
                    .withAudience(String.valueOf(userMember.getId()))          // 将 Id 保存到 token 里面
                    .sign(Algorithm.HMAC256(userMember.getPassWord()));   // 以 密码 作为 token 的密钥
            result.setToken(token);
            result.setOldToken(token);
        } catch (UnsupportedEncodingException ignore) {
            ignore.printStackTrace();
            log.info("token生成错误！" );
        }
        return token;
    }

    public UUserMember getAppUserMsg(String useId) {
        UUserMember uUserMember = new UUserMember();
        try {
            uUserMember = userMemberMapper.selectByPrimaryKey(Long.valueOf(useId));
        } catch (Exception e) {
            e.printStackTrace();
            log.info("token生成错误！" );
        }
        return uUserMember;
    }



    public BaseCommonResult<MemberLoginResponse> login(MemberRequest record) {
        String operatorid = null;
        try {
             operatorid = wechatService.getOpenid(record.getAppId());
        } catch (Exception e) {
           log.error("获取微信OPPENID错误:{}",e);
           ResultBuilder.fail("授权失败");
        }
        record.setAppId(operatorid);
        MemberLoginResponse result = new MemberLoginResponse();
        UUserMemberExample example = new UUserMemberExample();
        example.createCriteria().andAppIdEqualTo(record.getAppId());
        List<UUserMember> userMembers = userMemberMapper.selectByExample(example);
        UUserMember userMember = new UUserMember();
        if(userMembers.size() == 0){
            userMember.setCreateTime(new Date());
            userMember.setUserName(record.getUserName());
            userMember.setAppId(record.getAppId());
            userMember.setPicUrl(record.getPicUrl());
            userMemberMapper.insertSelective(userMember);
        }else{
            userMember = userMembers.get(0);
        }
            UserLoginDto loginDto = new UserLoginDto();
            loginDto.setChannelId(Constants.CHANNELID_XCX);
            loginDto.setUserType(Constants.USER_TYPE_MEMBER);
            MUserManual member = new MUserManual();
            member.setWfcode(userMember.getAppId());
            getToken(result, loginDto, member,userMember);
            result.setLoginAccount(userMember.getAppId());
            result.setLoginId(String.valueOf(userMember.getId()));
            result.setUserName(userMember.getUserName());
            result.setYuanBao(userMember.getYuanBao());
            result.setPrice(userMember.getPrice());
            result.setPicUrl(userMember.getPicUrl());
            result.setGold(userMember.getGold());
            result.setPhone(userMember.getPhone());
            result.setUserType(Constants.USER_TYPE_MEMBER);
            result.setButton(userMember.getButton());
        return ResultBuilder.success(result);
    }

    public BaseCommonResult loginOut(String code) {
//        TonKenUtile.loginOut(code,Constants.USER_TYPE_MEMBER,Constants.CHANNELID_XCX);
        return ResultBuilder.success();
    }
    //获取会员信息
    public BaseCommonResult getMoney(String code) {
        UUserMemberExample example = new UUserMemberExample();
        example.createCriteria().andAppIdEqualTo(code);
        List<UUserMember> uUserMembers = userMemberMapper.selectByExample(example);
        if (uUserMembers.size()<=0){
            return ResultBuilder.fail("非法请求");
        }
        return ResultBuilder.success(uUserMembers.get(0));
    }
    //添加会员收货地址
    @Transient
    public BaseCommonResult add(UMemberReceiveAddress request) {
        UMemberReceiveAddressExample example = new UMemberReceiveAddressExample();
        example.createCriteria().andMemberIdEqualTo(request.getMemberId()).andDefaultStatusEqualTo(0);
        List<UMemberReceiveAddress> uMemberReceiveAddresses = memberReceiveAddressMapper.selectByExample(example);
        if (uMemberReceiveAddresses.size()>0){
            UMemberReceiveAddress memberReceiveAddress = uMemberReceiveAddresses.get(0);
            if (request.getDefaultStatus()==0){
                memberReceiveAddress.setDefaultStatus(1);
                memberReceiveAddressMapper.updateByPrimaryKeySelective(memberReceiveAddress);
            }
        }else {
            //没有默认地址设置为默认
            request.setDefaultStatus(0);
        }
        int i = memberReceiveAddressMapper.insertSelective(request);
        return ResultBuilder.success(request);
    }
    //修改会员收货地址
    @Transient
    public BaseCommonResult update(MemberReceiveAddressReq request) {
        if (request.getIsDelete()!= null&&request.getIsDelete()==0){
            memberReceiveAddressMapper.deleteByPrimaryKey(request.getId());
            return ResultBuilder.success();
        }
        //默认地址修改
        if (request.getDefaultStatus()==0){
            UMemberReceiveAddressExample example = new UMemberReceiveAddressExample ();
            example.createCriteria().andMemberIdEqualTo(request.getMemberId()).andDefaultStatusEqualTo(0);
            List<UMemberReceiveAddress> uMemberReceiveAddresses = memberReceiveAddressMapper.selectByExample(example);
            if (uMemberReceiveAddresses.size()>0){
                UMemberReceiveAddress memberReceiveAddress = uMemberReceiveAddresses.get(0);
                UMemberReceiveAddress record = new UMemberReceiveAddress ();
                record.setId(memberReceiveAddress.getId());
                record.setDefaultStatus(1);
                memberReceiveAddressMapper.updateByPrimaryKeySelective(record);
            }
        }

        UMemberReceiveAddress map = dozerMapper.map(request, UMemberReceiveAddress.class);
        memberReceiveAddressMapper.updateByPrimaryKeySelective(map);
        return ResultBuilder.success(request);
    }
    //添加会员购物信息
    @Transient
    public BaseCommonResult addCar(MemberCarRequest request) {
        log.info("添加购物车请求参数:{}",request);
        if (request.getGoodsId()==null){
         return  ResultBuilder.fail("请选择商品!");
        }
        MMemberCar record = new MMemberCar();
        record.setMemberId(request.getMemberId());
        MMemberCarExample example = new MMemberCarExample();
        example.createCriteria().andMemberIdEqualTo(request.getMemberId());
        List<MMemberCar> mMemberCars = mMemberCarMapper.selectByExample(example);
        if (mMemberCars.size()>0){
            record = mMemberCars.get(0);
        }else {
            record.setCreateTime(new Date());
            mMemberCarMapper.insertSelective(record);
        }
        MMemberCarDetailExample memberCarDetailExample = new MMemberCarDetailExample ();
        memberCarDetailExample.createCriteria().andGoodsIdEqualTo(request.getGoodsId().longValue()).andMemberCarIdEqualTo(record.getId());
        List<MMemberCarDetail> mMemberCarDetails = mMemberCarDetailMapper.selectByExample(memberCarDetailExample);
        if (mMemberCarDetails.size()>0){
            return ResultBuilder.fail("此商品已在购物车");
        }
        //插入中间表
        MMemberCarDetail memberCarDetail = new MMemberCarDetail();
        memberCarDetail.setGoodsId(request.getGoodsId().longValue());
        memberCarDetail.setMemberCarId(record.getId());
        mMemberCarDetailMapper.insertSelective(memberCarDetail);
        return ResultBuilder.success(record);
    }
    //删除会员购物车
    @Transient
    public BaseCommonResult deleteCar(MemberCarRequest request) {
        log.info("会员购物车删除,请求参数为：{}", request);
        MMemberCarDetailExample example = new MMemberCarDetailExample();
        example.createCriteria().andGoodsIdEqualTo(request.getGoodsId().longValue()).andIdEqualTo(request.getMemberCarDetailId());
        int i = mMemberCarDetailMapper.deleteByExample(example);
        log.info("会员购物车删除,成功：{}", i);
        return ResultBuilder.success();
    }
    //查询会员购物车
    public BaseCommonResult<BasePage<MemberCarResult>> memberCarList(MemberCarListRequest request) {
        BasePage<MemberCarResult> pageResult = new BasePage();
        log.info("会员购物车列表,请求参数为：{}", request);
        try {
            PageHelper.startPage(request.getPage(), request.getPageSize());
            List<MemberCarResult> list= memberCarMapper.selectMemberCarList(request.getMemberId());
            PageInfo<MemberCarResult> pageInfo = new PageInfo<>(list);
            pageResult.setList(list);
            pageResult.setPageInfo(pageInfo.getPageNum(), pageInfo.getPageSize(), pageInfo.getPages(), pageInfo.getTotal());
        }catch (GoodsException e) {
            log.info("会员购物车列表异常，异常信息为：{}", e);
            ResultBuilder.fail("系统异常");
        }
        log.info("会员购物车列表接口结束");
        return ResultBuilder.success(pageResult);
    }
    //查询会员收货地址
    public BaseCommonResult getAddress(AddressRequest addressRequest) {
        UMemberReceiveAddressExample example = new UMemberReceiveAddressExample();
        UMemberReceiveAddressExample.Criteria criteria = example.createCriteria();
        criteria.andMemberIdEqualTo(Long.parseLong(addressRequest.getUserId()));
        if (addressRequest.getAddressId() != null){
            criteria.andIdEqualTo(Long.parseLong(addressRequest.getAddressId()));
        }
        if (addressRequest.getDefaultStatus() != null){
            criteria.andDefaultStatusEqualTo(addressRequest.getDefaultStatus());
        }
        List<UMemberReceiveAddress> uMemberReceiveAddresses = memberReceiveAddressMapper.selectByExample(example);
        return ResultBuilder.success(uMemberReceiveAddresses);
    }

    /**
     * 手机号正则表达式
     * @param str
     * @return
     */
    public static boolean isMobile(String str) {
        Pattern p = null;
        Matcher m = null;
        boolean b = false;
        String s2="^[1](([3|5|8][\\d])|([4][4,5,6,7,8,9])|([6][2,5,6,7])|([7][^9])|([9][1,8,9]))[\\d]{8}$";// 验证手机号
        if(StringUtils.isNotBlank(str)){
            p = Pattern.compile(s2);
            m = p.matcher(str);
            b = m.matches();
        }
        return b;
    }
    public BaseCommonResult binding(BinDingPhonRequest request) {
        boolean mobile = isMobile(request.getPhone());
        if (!mobile){
            return  ResultBuilder.fail("手机格式不正确!");
        }
        UUserMember record = new UUserMember ();
        record.setId(request.getMemberId());
        record.setPhone(request.getPhone());
        userMemberMapper.updateByPrimaryKeySelective(record);
        return ResultBuilder.success(record);
    }

    /**
     * 获取用户金额
     * @param memberId
     * @return
     */
    public BaseCommonResult<MemberPriceReslut> getlogin(Long memberId) {
        UUserMember uUserMember = userMemberMapper.selectByPrimaryKey(memberId);
        MemberPriceReslut map = dozerMapper.map(uUserMember, MemberPriceReslut.class);
        //获取用户卖出物品
        MRecoveryGoodsExample recoveryGoodsExample = new MRecoveryGoodsExample ();
        recoveryGoodsExample.createCriteria().andMemberIdEqualTo(uUserMember.getId()).andOrderStateEqualTo(4);
        long r = recoveryGoodsMapper.countByExample(recoveryGoodsExample);
        map.setTcount(r);
        //获取用户首次购买
        POrdersExample ordersExample = new POrdersExample ();
        ordersExample.createCriteria().andUserIdEqualTo(memberId).andOrderNoEqualTo("6").andOrderNoEqualTo("5");
        long o = ordersMapper.countByExample(ordersExample);
        map.setYcount(o);
        //获取用户满100鱿费可领取次数
        MemberSumPrice price = tradeAdminMapper.selectSumPrice(memberId);
        BigDecimal divide = price.getPrice().divide(new BigDecimal(100), 2, BigDecimal.ROUND_DOWN);
        map.setLcount(divide.intValue());
        return ResultBuilder.success(map);
    }

    /**
     * 任务领取奖励
     * @param memberId
     * @param type
     * @return
     */
    @Transient
    public BaseCommonResult<UUserMember> getjinbi(Long memberId, int type) {
        //1:关注公众号,2登录领取,3首次卖出,4首次购买,5鱿费获取
        UUserMemberExample example = new UUserMemberExample ();
        example.createCriteria().andIdEqualTo(memberId);
        List<UUserMember> uUserMembers = userMemberMapper.selectByExample(example);
        if (uUserMembers.size()>0){
            log.info("任务领取奖励memberId,type:{},{}",memberId,type);
            UUserMember uUserMember = uUserMembers.get(0);
            MMemberJb record = new MMemberJb ();
            uUserMember.setGold(uUserMember.getGold().add(new BigDecimal(20000)));
            uUserMember.settGold(uUserMember.gettGold().add(new BigDecimal(20000)));//累计金币
            if (type == 1){//1:关注公众号
                BigDecimal gold = uUserMember.getGold();
                uUserMember.setGold(gold.add(new BigDecimal(10000)));
                uUserMember.settGold(uUserMember.gettGold().add(new BigDecimal(10000)));//累计金币
                uUserMember.setgType(0);
                record.setName("关注公众号");
                userMemberMapper.updateByPrimaryKeySelective(uUserMember);
            }else if (type == 2){//2登录领取
                uUserMember.setGold(uUserMember.getGold().add(new BigDecimal(108)));
                uUserMember.settGold(uUserMember.gettGold().add(new BigDecimal(108)));//累计金币
                uUserMember.setcType(0);
                record.setName("登录账号");
                userMemberMapper.updateByPrimaryKeySelective(uUserMember);
            }else if (type == 3){//3首次卖出
                uUserMember.settType(0);
                record.setName("首次卖出物品");
                userMemberMapper.updateByPrimaryKeySelective(uUserMember);
            }else if (type == 4){//4首次购买
                uUserMember.setwType(0);
                record.setName("首次购买物品");
                userMemberMapper.updateByPrimaryKeySelective(uUserMember);
            }else if (type == 5){//5鱿费获取
                MemberSumPrice price = tradeAdminMapper.selectSumPrice(memberId);
                BigDecimal divide = price.getPrice().divide(new BigDecimal(100), 2, BigDecimal.ROUND_DOWN);
                if (divide.intValue()<=uUserMember.getlType()){
                    return ResultBuilder.fail("领取次数不足");
                }
               int i = uUserMember.getlType()+1;
                log.info("已领次数:{}",i);
                uUserMember.setlType(i);
                record.setName("每获得100鱿费");
                userMemberMapper.updateByPrimaryKeySelective(uUserMember);
            }
            record.setCreateTime(new Date());
            record.setMemberId(uUserMember.getId());
            record.setPrice(uUserMember.getGold());
            record.setType(1);
            memberJbMapper.insertSelective(record);
            log.info("任务领取奖励memberId:{}",uUserMember.getId());
            return ResultBuilder.success(uUserMember);
        }else {
            return ResultBuilder.fail("用户不存在");
        }
    }

    /**
     * 1:鱿费,2金币,3现金
     * @param memberId
     * @param type
     * @return
     */
    public BaseCommonResult<List<GetMemberResult>> getmember(Long memberId, int type) {
        List<GetMemberResult> getMemberResults = new ArrayList<>();
        if (type == 1){
            getMemberResults = memberOrderMapper.selectYouFei(memberId);
        }else  if (type ==2){
            MMemberJbExample example = new MMemberJbExample ();
            example.createCriteria().andMemberIdEqualTo(memberId);
            List<MMemberJb> mMemberJbs = memberJbMapper.selectByExample(example);
            for (MMemberJb jb:mMemberJbs) {
                GetMemberResult map = dozerMapper.map(jb, GetMemberResult.class);
                getMemberResults.add(map);
            }
        }else {
            getMemberResults = memberOrderMapper.selectPrice(memberId);
        }
        return ResultBuilder.success(getMemberResults);
    }

    /**
     * 鱿费 现金收益
     * @param memberId
     * @return
     */
    public BaseCommonResult<MemberWalletResult> getMemberWallet(Long memberId) {
        UUserMember uUserMember = userMemberMapper.selectByPrimaryKey(memberId);
        if (uUserMember != null){
            ResultBuilder.fail("用户不存在");
        }
        MemberWalletResult map = dozerMapper.map(uUserMember, MemberWalletResult.class);
        List<GetMemberResult> getMemberResults = memberOrderMapper.selectMemberWallet(memberId);
        if (getMemberResults.size()>0){
            map.setGetMemberResults(getMemberResults);
        }
        return ResultBuilder.success(map);
    }

    /**
     * 1:解锁10元,2解锁30元,3解锁50元,4解锁100元
     * 100000，300000，500000，1000000
     * @param memberId
     * @param type
     * @return
     */
    @Transient
    public BaseCommonResult getMoney(Long memberId, int type) {
        UUserMember uUserMember = userMemberMapper.selectByPrimaryKey(memberId);
        BigDecimal gold = uUserMember.getGold();
        MMemberJb record = new MMemberJb ();
        if (type == 1){
            if (gold.intValue()<100000){
                ResultBuilder.fail("金币不够");
            }
            uUserMember.setGold(gold.subtract(new BigDecimal(100000)));
            record.setPrice(new BigDecimal(100000));
        }else if (type == 2){
            if (gold.intValue()<300000){
                ResultBuilder.fail("金币不够");
            }
            uUserMember.setGold(gold.subtract(new BigDecimal(300000)));
            record.setPrice(new BigDecimal(300000));
        }else if (type == 3){
            if (gold.intValue()<500000){
                ResultBuilder.fail("金币不够");
            }
            uUserMember.setGold(gold.subtract(new BigDecimal(500000)));
            record.setPrice(new BigDecimal(500000));
        }else {
            if (gold.intValue()<1000000){
                ResultBuilder.fail("金币不够");
            }
            uUserMember.setGold(gold.subtract(new BigDecimal(1000000)));
            record.setPrice(new BigDecimal(1000000));
        }
        userMemberMapper.updateByPrimaryKeySelective(uUserMember);
        record.setMemberId(memberId);
        record.setCreateTime(new Date());
        record.setType(2);
        memberJbMapper.insertSelective(record);
        return ResultBuilder.success(uUserMember);
    }
}
