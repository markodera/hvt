import sys
path = 'c:/Users/MARK/Documents/GitHub/hvt/hvt/apps/authentication/adapters.py'
with open(path, 'r', encoding='utf-8') as f:
    s = f.read()

target = '''        user = super().save_user(request, sociallogin, form)
        api_key = getattr(request, "auth", None)'''

replacement = '''        user = super().save_user(request, sociallogin, form)
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"DEBUG SAVE_USER request type: {type(request)}")
        logger.error(f"DEBUG SAVE_USER request.auth: {getattr(request, 'auth', 'MISSING')}")
        api_key = getattr(request, "auth", None)'''

s2 = s.replace(target.replace('\r\n', '\n'), replacement.replace('\r\n', '\n'))
if s == s2:
    s2 = s.replace(target.replace('\n', '\r\n'), replacement.replace('\n', '\r\n'))

with open(path, 'w', encoding='utf-8') as f:
    f.write(s2)
print("done")
