#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include "main.cpp"

class TestRunner {
private:
    int totalTests = 0;
    int passedTests = 0;
    Logger logger;

public:
    TestRunner() : logger("test_results.log") {}

    template<typename T>
    void AssertEqual(const T& expected, const T& actual, const std::string& testName) {
        totalTests++;
        if (expected == actual) {
            passedTests++;
            logger.Log("PASSED: " + testName);
        } else {
            logger.Log("FAILED: " + testName + " - Expected: " + std::to_string(expected) + 
                      ", Actual: " + std::to_string(actual), true);
        }
    }

    void RunTests() {
        TestSecurityManager();
        TestProcessManager();
        TestArgumentParser();
        PrintResults();
    }

private:
    void TestSecurityManager() {
        SecurityManager security;
        AssertEqual(true, security.PerformSecurityChecks(), "SecurityManager::PerformSecurityChecks");
    }

    void TestProcessManager() {
        Logger testLogger("test.log");
        ProcessManager processManager(testLogger);
        
        // Test with invalid session ID
        HANDLE invalidHandle = processManager.GetProcessHandleBySessionID(999999);
        AssertEqual(nullptr, invalidHandle, "ProcessManager::GetProcessHandleBySessionID with invalid ID");
    }

    void TestArgumentParser() {
        const char* testArgs[] = {
            "program.exe",
            "--session",
            "1",
            "--process",
            "test.exe"
        };
        
        ArgumentParser parser(5, const_cast<char**>(testArgs));
        AssertEqual(true, parser.Parse(), "ArgumentParser::Parse");
        AssertEqual(1u, parser.GetTargetSessionID(), "ArgumentParser::GetTargetSessionID");
        AssertEqual(std::string("test.exe"), parser.GetTargetProcessName(), "ArgumentParser::GetTargetProcessName");
    }

    void PrintResults() {
        std::cout << "\nTest Results:" << std::endl;
        std::cout << "Total Tests: " << totalTests << std::endl;
        std::cout << "Passed Tests: " << passedTests << std::endl;
        std::cout << "Failed Tests: " << (totalTests - passedTests) << std::endl;
        std::cout << "Success Rate: " << (static_cast<double>(passedTests) / totalTests * 100) << "%" << std::endl;
    }
};

int main() {
    TestRunner runner;
    runner.RunTests();
    return 0;
} 