Project: emailvalidation
* Write scaffolding for the email validator project. It's a stand-alone html page with vanilla js/css. 
* Html/css/js/unit tests should be in separate files. 
* The emails folder contains sample emails
* The code should have clear separation of responsibility
* Only calls allowed are dns calls to get relevant spf/dkim/dmarc info
* Let's start with simple page, a parser js object which extract spf/dkim/dmarc/etc information, and returns an object which is then used to render a tree with all parsed information.