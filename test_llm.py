import json
import os
from core.llm_adapter import create_llm, OllamaLLM

def test_ollama_analyze():
    # 从配置文件加载 Ollama 配置
    config_path = os.path.join(os.path.dirname(__file__), 'configs', 'providers.json')
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            providers = json.load(f)
        
        # 查找 Ollama 配置
        ollama_config = None
        for p in providers:
            if p.get('name') == 'Ollama':
                ollama_config = p
                break
        
        if not ollama_config:
            print("错误：未找到 Ollama 配置")
            return
        
        print("加载的 Ollama 配置:")
        print(json.dumps(ollama_config, indent=2, ensure_ascii=False))
        print("\n" + "="*50 + "\n")
        
        # 创建 OllamaLLM 实例
        llm = create_llm(ollama_config)
        print("OllamaLLM 实例创建成功")
        
        # 测试连接
        print("\n测试连接...")
        success = llm.test_connection()
        if success:
            print("连接成功！")
        else:
            print("连接失败！")
            return
        
        # 测试 analyze 方法
        print("\n" + "="*50)
        print("测试 analyze 方法 - SQL 注入检测")
        print("="*50)
        
        test_log = "GET /login.php?user=admin' OR '1'='1 HTTP/1.1"
        print(f"\n测试日志: {test_log}")
        print("\n正在分析...")
        
        result = llm.analyze(test_log)
        print("\n分析结果:")
        print(json.dumps(result, indent=2, ensure_ascii=False))
        
        # 检查是否识别出 SQL 注入
        findings = result.get('findings', [])
        if findings:
            for finding in findings:
                if finding.get('type') == 'SQLI':
                    print("\n✅ 成功识别 SQL 注入攻击！")
                    print(f"   严重程度: {finding.get('severity')}")
                    print(f"   描述: {finding.get('description')}")
                    print(f"   置信度: {finding.get('confidence')}/10")
                    return
            print("\n⚠️ 识别到威胁，但不是 SQL 注入")
        else:
            print("\n❌ 未识别到威胁（可能需要调整提示词或模型）")
            
    except Exception as e:
        print(f"测试出错: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    test_ollama_analyze()