'''
@app.route('/Java/')
def java():
    try:
        return render_template("Java.html", page_dict=page_dict)

    except Exception as e:
        return(str(e))
'''
# This will import a dictionary I previously defined. The diction has three separate values associated with it;
# location, language, and tutorial
# This file will pull the dictionary information, and create all of the app.route we will require for Meraki
from content_management import Content

# declare a dictionary variable from the content_management py file
page_dict = Content()

# function with arguments (language, tutorial)
def create_list(l, t):
    language = l
    tab = "    "
    print (tab)
    print ("@app.route('/" + language + "/" + t + "/')")
    print ("@login_required")
    print ("def " + language.lower() + "_" + t + "():")
    print (tab + "un = get_un()")
    print (tab + "try:")
    print (tab + tab +"return render_template(\"languages/" + language + "/" + t +".html\", page_dict=page_dict, un=un)")
    print (tab)
    print (tab + "except Exception as e:")
    print (tab + tab + "return(str(e))")
    print (tab)


# The following will print out each individual tutorial I have defined inside of content_management
for a in page_dict["AngularJS"]:
       create_list("AngularJS", a[2])

#      create_list(language, tutorial)

for c in page_dict["C_PlusPlus"]:
       create_list("C_plusplus", c[2])

for d in page_dict["C_Sharp"]:
        create_list("C_sharp", d[2])

for j in page_dict["Java"]:
        create_list("Java", j[2])

for js in page_dict["Javascript"]:
        create_list("Javascript", js[2])

for p in page_dict["Python"]:
        create_list("Python", p[2])

