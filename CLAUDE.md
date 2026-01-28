Project: emailvalidation
* a stand-alone html page, which accepts a raw source email(a text area which allows to paste it or drag and drop an eml file) and validates it, all code runs in client browser
    * parses an email, prepares all necessary objects containing parsing results for dkim/spf/dmarc policies
        * parsing should be covered by tests, use email examples in emails folder
    * renders a modern responsible html page with cards containing validation/debug information from the parsed email
* separate files for vanilla js, html, css and unit tests
* emails folder contains sample emails