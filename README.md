Project : Item Catlog
======================================
This project is mainly intended to allow the user to add a Category and items under the selected category.
The user can only edit and delete the categories or items which he has created.
JSON endpoints are provided for the Categorywise items list,category list,Items of selected categories
and individual item information.
User can create his own profile and login to the system.User passwords are hashed and stored in the database.
Also user is allowed to login using his own gmail id using oauth2.


Prerequisites
============
1. Python 3.6 



softwares installed
==================
	1. Clone the project
	==================
	#git clone https://github.com/SonaliHomkar/ProjectItemCatlog_19Feb.git

	2. install the following packages
		1. re
		2. sys
		3. logging
		4. traceback
		5. hmac
		6. random
		7. hashlib
		8. os
		9.string
		10. sqlalchemy
		11. sqlalchemy.orm
		12. flask
		13. oauth2client
		14. flask
		15. httplib2
		16. json
		17. requests
		18. functools
  

	

Getting Started
==============
1. compile and run ItemCatlog.py

Running the tests
========================
1. After compiling the file ItemCatlog.py please open the browser and type http://localhost:5500/
2. It will open the login Page. The user can log in using his gmail id or application's user Id
3. User can create his own userId using link New User sign up form
4. Once he successfully creates his user Id he can login with his credentials.
5. After login user is able to see home page where all the categories are listed with
   few list of item which are created recently
6. When the user clicks on category it displays list of items created under that category.
7. When the user clicks on item it displays detailed information about the item
8. If the user has created the item then only he can see the Edit and delete button on the screen.
9. If the user clicks on Edit button the form opens in edit mode and user can edit the item details.
10. If the user cllicks on Delete button it displays a screen to confirm the deletion and when clicked submit button
    he is allowed to delete the items
11. All the screens are validating madatory fields.
12. Please type URL http://localhost:5500/ItemCatlog/JSON to display the Categorywise Item list  in JSON format
13. A logout button is displayed on all the screens to logout the user at any point of time
14. Apart from the required functionality user is allowed to edit category 
using URL http://localhost:5500/ItemCatlog/<int:cat_id>/EditItem/
15. Also the user is allowed to delete category 
using URL http://localhost:5500/ItemCatlog/<int:cat_id>/DeleteItem/
16. User can see the list of categories using endpoint http://localhost:5500/ItemCatlog/Catlist
17. User can see the list of Items of given category using endpoint http://localhost:5500/ItemCatlog/<int:cat_id>/CatItems/
18. User can see the individual items information using endpoint http://localhost:5500/ItemCatlog/<int:item_id>/Items/



