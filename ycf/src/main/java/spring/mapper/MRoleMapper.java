package spring.mapper;

import java.util.List;
import org.apache.ibatis.annotations.Param;
import spring.model.MRole;
import spring.model.MRoleExample;

public interface MRoleMapper {
    long countByExample(MRoleExample example);

    int deleteByExample(MRoleExample example);

    int deleteByPrimaryKey(Long roleId);

    int insert(MRole record);

    int insertSelective(MRole record);

    List<MRole> selectByExample(MRoleExample example);

    MRole selectByPrimaryKey(Long roleId);

    int updateByExampleSelective(@Param("record") MRole record, @Param("example") MRoleExample example);

    int updateByExample(@Param("record") MRole record, @Param("example") MRoleExample example);

    int updateByPrimaryKeySelective(MRole record);

    int updateByPrimaryKey(MRole record);
}