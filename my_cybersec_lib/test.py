from SecureTool.Password import PasswordStrengthChecker

checker = PasswordStrengthChecker(username="alan")
result = checker.check_strength("pass1234!")
print(result)
