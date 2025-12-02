Description
-
xss-detection-system is the first version with old structure that doesn't combine ML and WAF into one component yet.

xss-detection-system real is the second version with new structure that combines ML and WAF into one component, though the real flow is that the request reaches WAF first and then reaches ML, and has bugs and errors.

xss-detection-system-gcloud is the third and final version. This version is ready to be deployed on the Google Cloud platform. It can be deployed locally by using Docker as well, without further modification. Use the same structure as the second version. No bugs. Every component can be used.

After deploy
-
1.) Go to http://localhost:8000/install.php to install bWAPP databse first

2.) Every page validate the input so user can XSS attack any input in any page other than XSS related page as well.

3.) Go to http://localhost:5601/ to use Kibana, search and choose **index management** then choose blocked-requests and create view to view log.

4.) http://localhost:7474/ to use Neo4j. Log in with username **neo4j** and password **SecureGCPPassword123!**


# Misc.
`IMPLEMENTATION_SUMMARY.md`, `NEO4J_VISUALIZATION_QUERIES.md`, and `DETAILED_EXPLANATIONS.md` are information for **`xss-detection-system-gcloud-2`**. It explain how you can manually retrain the model and swap it. It also explain extra information of this architecture.
