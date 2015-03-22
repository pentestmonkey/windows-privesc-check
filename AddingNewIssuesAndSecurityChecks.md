# How to add new issues to windows-privesc-check #

There are essentially 3 things you need to do to add a new issue:
  1. Write the code that checks for the presence of the issue (obviously)
  1. Write the text of the issue
  1. (perhaps also) write some code to include supporting data in your issue text

## 1. Writing the security check ##

You should add your check to windows-privesc-check.py.  Here's an example check:

```
		# Check that the binary name is properly quoted
		if str(s.get_exe_path_clean()).find(" ") > 0: # clean path contains a space
			if str(s.get_exe_path()).find(str('"' + s.get_exe_path_clean()) + '"') < 0: # TODO need regexp.  Could get false positive from this.
				report.get_by_id("WPC051").add_supporting_data('service_info', [s])
```

The important thing to note is eventually you'll end up calling "report.get\_by\_id("WPCNNN").add\_supporting\_data('type of supporting data', [datastructure, datastructure, ...]

The issue reference "WPCNNN" is described below, followed by how the supporting data works.

## 2. Writing the issue ##

Open up wpc/conf.py and locate the (long) dictionary "issue\_template".  You'll see issue text for WPC001, WPC002, ... Add your issue to the end of it.  Copy and paste an earlier one as a template.  The only part likely to cause confusion is the "supporting\_data" bit which is explained below.

## 3. Adding supporting data ##

In wpc/conf.py you'll have something that looks like this:
```
       'supporting_data': {
          'service_info': {
             'section': "description",
             'preamble': "The following services have insecurely quoted paths:",
          },
       }
```

It describes how to add supporting data to an issue.
  * section: States whether the supporting data appears under the "description" or the "recommendation".  You usally want "description".
  * preamble: Is some static text that goes before your supporting data.
  * service\_info: this is the type of supporting data.  It's just a string you choose.  If another issue already reports supporting data in the format you want, use it.  If not you'll have to define your own.  The string you use must match the type of supporting data saved when you called "add\_supporting\_data" from windows-privesc-check.py:
```
report.get_by_id("WPC051").add_supporting_data('service_info', [s])
```

Any data structure you need to generate your supporting data must be passed as the second argument to "add\_supporting\_data".

So how does wpc know how to display the supporting data?  Open up wpc/report/issue.py and locate the "render\_supporting\_data" method.  It contains an "if" statement for every possible type of supporting data - "service\_info" is an example of a type of supporting data.  It is called to convert the data structures you passed to "add\_supporting\_data" into text for the report.

You should check the supporting data type you want to use is in issue.py.  Add a new "if" clause for it if not.