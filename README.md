# Sukabumi Auto Config (Demo Version)
using python 3.7.3<br>
<br>
depedency<br>
- django<br>
- django-session-timeout<br>
- djangorestframework<br>
- paramiko<br>
- xhtml2pdf<br>
- xlwt<br>
- requests<br>
- mysqlclient<br>
<br>
<br>
create trigger for table log_user<br>
<br>
CREATE TRIGGER `delete_Session`<br> 
AFTER DELETE ON `django_session`<br>
FOR EACH ROW<br>
DELETE FROM auto_tl1_useractive WHERE auto_tl1_useractive.sessionid = OLD.session_key<br>