package spring.service.impl;

import org.springframework.data.annotation.Transient;
import spring.dto.BaseCommonResult;
import spring.dto.request.UserAccountRequest;
import spring.dto.request.UserLoginDto;
import spring.dto.result.UserLoginResponse;
import spring.enums.UserErrorCodeEnum;
import spring.mapper.MUserMapper;
import spring.model.MUser;
import spring.model.MUserExample;
import spring.model.MUserManual;
import spring.service.UserCommonRegistryService;
import spring.utils.Constants;
import spring.utils.MD5;
import spring.utils.ResultBuilder;
import spring.utils.TonKenUtile;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 管理人员接口
 */
@Slf4j
@Service
public class UserCommonRegistryServiceImpl implements UserCommonRegistryService {

    @Autowired
    private MUserMapper userMapper;

    @Override
    @Transient
    public BaseCommonResult updateAccount(UserAccountRequest request) {
        MUser user = new MUser();
        BeanUtils.copyProperties(request,user);
        int i = userMapper.updateByPrimaryKeySelective(user);
        log.info("插入数据成功: {}",user);
        BaseCommonResult result = new BaseCommonResult();
        result.setCode(UserErrorCodeEnum.SUCCESS.getCode());
        result.setMsg(UserErrorCodeEnum.SUCCESS.getMsg());
        result.setData(user);
        return beanUtils(result, user);
    }

    @Override
    public BaseCommonResult<UserLoginResponse> userLogout(UserLoginDto loginDto) {
        TonKenUtile.loginOut(loginDto.getAccount(), Constants.USER_TYPE_BACKEND,Constants.CHANNELID_PC);
        return ResultBuilder.success();
    }

    @Override
    @Transient
    public BaseCommonResult createAccount(UserAccountRequest request) {
        MUser user = new MUser();
        request.setPassWord(MD5.MD5(request.getPassWord()));
        BeanUtils.copyProperties(request,user);
        int i = userMapper.insertSelective(user);
        log.info("插入数据成功: {}",user);
        BaseCommonResult result = new BaseCommonResult();
        return beanUtils(result, user);
    }

    @Override
    public BaseCommonResult<UserLoginResponse> userLogin(UserLoginDto loginDto) {
        UserLoginResponse result = new UserLoginResponse();
        MUserExample example = new MUserExample();
        example.createCriteria().andLoginAccountEqualTo(loginDto.getAccount());
        List<MUser> mUsers = userMapper.selectByExample(example);

        if (mUsers.size()<=0){
            return ResultBuilder.fail("用户不存在");
        }
        MUser mUser = mUsers.get(0);
        if (!mUser.getPassWord().equals(MD5.MD5(loginDto.getPassword()))){
            return ResultBuilder.fail("密码错误");
        }
        loginDto.setUserType(Constants.USER_TYPE_BACKEND);
        loginDto.setChannelId(Constants.CHANNELID_PC);
        MUserManual userManual = new MUserManual();
        userManual.setWfcode(String.valueOf(mUser.getUserId()));
        TonKenUtile.setResultToken(result, loginDto, userManual);
        result.setLoginAccount(mUser.getLoginAccount());
        result.setUserName(mUser.getUserName());
        result.setLoginId(String.valueOf(mUser.getUserId()));
        result.setUserType(Constants.USER_TYPE_BACKEND);
        return ResultBuilder.success(result);
    }

    public BaseCommonResult beanUtils(BaseCommonResult result, Object t){
        result.setCode(UserErrorCodeEnum.SUCCESS.getCode());
        result.setMsg(UserErrorCodeEnum.SUCCESS.getMsg());
        result.setData(t);
        return result;
    }
}
