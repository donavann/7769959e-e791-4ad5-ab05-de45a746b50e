/* hasher.go
 *
 * A simple password hashing web server, performed as part of a pre-employment exercise.
 */

package main

import (
        "crypto/sha512"
        "encoding/base64"
        "encoding/json"
        "fmt"
        "net/http"
        "os"
        "regexp"
        "strconv"
        "strings"
        "sync"
        "sync/atomic"
        "time"
)

// Variables related to hashing
var g_activeHashThreads int64                   // Keep track of the number of threads actively hashing passwords (this will be treated as an atomic)
var g_transactionSerial uint64                  // give out a unique serial number for each encryption request -- this is not very secure (this is an atomic)
var g_shaValueMapMutex = &sync.Mutex{}          // g_shaValueMapMutex protects access to g_shaValueMap
var g_shaValueMap = make (map [uint64] string)  // Map to store key (uint64) value (string) pairs in

// Variables related to stats tracking
var g_statsMutex = &sync.Mutex{}                // g_statsMutex protects both g_statsTransactionCount and g_statsTransactionCumulativeTime
var g_statsTransactionCount uint64              // total number of hash transactions processed
var g_statsTransactionCumulativeTime uint64     // total amount of time (in nanoseconds (10^-9)) used calculating hashes

// Variables related to shutdown tracking
var g_shutdownMutex = &sync.Mutex{}             // g_statsMutex protects g_pendingShutdown
var g_pendingShutdown bool                      // flag that tracks if the process is in quiescent state


/*
 *************************************************
 *       main and support functions
 */

func main () {

   go exitIfProcessingCompleteAndShutdownFlag()   // Start the shutdown monitoring thread

   http.HandleFunc ("/", httpRequestRouter)
   http.ListenAndServe (":8888", nil)             // Start the web server
}

// Monitor if shutdown has been requested and verify no hash threads remain active
func exitIfProcessingCompleteAndShutdownFlag() {

   for {
      g_shutdownMutex.Lock()

      if true == g_pendingShutdown && 0 == atomic.LoadInt64(&g_activeHashThreads) {
         os.Exit (0)
      }
      g_shutdownMutex.Unlock()

      time.Sleep(time.Millisecond * 50)  // snooze 50 ms (1/20th of a second), when idle this keeps the process off the active list.
   }
}

/*
 *************************************************
 *       http server related
 */

var g_regHashReq = regexp.MustCompile ("/hash$")         // /hash
var g_regHashFetch = regexp.MustCompile ("/hash/\\d+$")  // /hash/ followed by digits
var g_regStats = regexp.MustCompile ("/stats$")          // /stats
var g_regShutdown = regexp.MustCompile ("/shutdown$")    // /shutdown

// Basic HTTP request router based on URL paths
func httpRequestRouter (response http.ResponseWriter, request *http.Request) {

   switch request.Method {

      case "GET":
         switch {
            // Fetch hashed password result
            case g_regHashFetch.MatchString (request.URL.Path):
               processHashFetch (response, request.URL.Path)

            // Dump stats request
            case g_regStats.MatchString (request.URL.Path):
               processStatsRequest (response)

            // Initiate shutdown sequence
            case g_regShutdown.MatchString (request.URL.Path):
               processShutdownRequest (response)

            // for all malformed, invalid, not existent URLs
            default:
               httpError (response, http.StatusNotFound, "Unknown URL path `" + request.URL.Path + "` encountered in " + request.Method + " request")
         }

      case "POST":
         switch {
            // Perform a password hash request
            case g_regHashReq.MatchString (request.URL.Path):
               // make sure a shutdown has not been requested
               g_shutdownMutex.Lock()
               if true == g_pendingShutdown {
                  httpError (response, http.StatusServiceUnavailable, "shutdown underway")
                  g_shutdownMutex.Unlock()
                  return
               }
               g_shutdownMutex.Unlock()

               atomic.AddInt64(&g_activeHashThreads, 1)
               processHashRequest (response, request)

            // for all malformed, invalid, not existent URLs
            default:
               httpError (response, http.StatusNotFound, "Unknown URL path `" + request.URL.Path + "` encountered in " + request.Method + " request")
         }

      default:
         httpError (response, http.StatusMethodNotAllowed, "Unsupported Method Type: " + request.Method )
   }
}

// Generic error handler, set the http status code and return a message to the requester
func httpError (response http.ResponseWriter, status int, message string) {

   response.WriteHeader (status)
   fmt.Fprintf (response, message + "\n")
}

/*
 *************************************************
 *       http server request processing
 */

func processHashFetch (response http.ResponseWriter, url string) {

   // The last field in the path contains the key we need to locate
   // Tokenize the path and grab the last field
   urlTokens := strings.Split (url, "/")
   keyStr := string (urlTokens[len (urlTokens) - 1])

   // Convert string token to an integer
   key, err := strconv.Atoi (keyStr)

   if nil != err {
      // This should really happen, as the regular expression match prevents anything but /hash/[digits] in the url, so Atoi should always work
      httpError (response, http.StatusBadRequest, "Invalid key encountered")
      return
   }

   // Check for the key in the map
   g_shaValueMapMutex.Lock()
   value, ok := g_shaValueMap[uint64(key)]
   g_shaValueMapMutex.Unlock()

   if false == ok {
      // key not found (or isn't ready yet)
      httpError (response, http.StatusBadRequest, "requested key and token data not ready or invalid key submitted")
      return
   }

   // Populate the response message with the sha value
   fmt.Fprintf (response, "%s\n", value)
}

func processHashRequest (response http.ResponseWriter, request *http.Request) {

   // Get the password value from the post data
   password := request.PostFormValue ("password")

   // Verify the password field was present and has data, otherwise give up
   if len (password) < 1 {
      atomic.AddInt64(&g_activeHashThreads, -1)
      httpError (response, http.StatusBadRequest, "malformed post data")
      return
   }

   // Get a new map key and prepare to respond to the client with the key
   key := atomic.AddUint64 (&g_transactionSerial, 1)
   fmt.Fprintf (response, "%d\n", key)

   // Create a thread to perform the hash calculation
   go calculateHash (key, password)
}

func calculateHash (key uint64, password string) {

   // sleep 5 seconds per spec
   time.Sleep (time.Second * 5)

   // Calculate the SHA512
   shaComputeStart := time.Now()
   shaBinary := sha512.Sum512 ([]byte(password))
   shaSumValue := base64.StdEncoding.EncodeToString (shaBinary[:])
   shaComputeEnd := time.Now()

   // Add the new SHA512 to the map
   g_shaValueMapMutex.Lock()
   g_shaValueMap[key] = shaSumValue
   g_shaValueMapMutex.Unlock()

   // Update the SHA512 timing data
   g_statsMutex.Lock()
   g_statsTransactionCount++

   duration := shaComputeEnd.Sub (shaComputeStart)  // duration is in nanoseconds (10^-9)

   g_statsTransactionCumulativeTime += uint64 (duration)

   // manual test point, on my system performance is always sub millisecond
   /* donavan@f238:~/src/jumpcloud $ go run hasher.go 
    * duration  42.757µs   cumulative  42757
    * duration  22.447µs   cumulative  65204
    * duration  22.084µs   cumulative  87288
    * duration  18.76µs   cumulative  106048
    * duration  21.873µs   cumulative  127921
    * duration  18.503µs   cumulative  146424
    */
   //fmt.Println ("duration ", duration, "  cumulative ", g_statsTransactionCumulativeTime)

   g_statsMutex.Unlock()

   // reduce the count of active hash threads
   atomic.AddInt64(&g_activeHashThreads, -1)
}

func processShutdownRequest (response http.ResponseWriter) {

   g_shutdownMutex.Lock()
   defer g_shutdownMutex.Unlock()
   g_pendingShutdown = true

   fmt.Fprintf (response, "shutdown sequence initiated\n")
}

func processStatsRequest (response http.ResponseWriter) {

   type StatsReport struct {
      Total uint64     // Total number of hashes calculated
      Average uint64   // average time to process sha512 call in milli (10^-3) seconds
   }

   var report StatsReport   // Create an instance so we can populate

   // Lock the mutex to protect stats data during acquisition.
   g_statsMutex.Lock()

   // Populate the `report`
   if g_statsTransactionCount > 0 {
      report.Total = g_statsTransactionCount
      // The project asked for this to be in milliseconds, g_statsTransactionCumulativeTime is stored in nanoseconds
      // on my system, this turns into a zero since most transactions are in the sub 30 microsecond range
      report.Average = g_statsTransactionCumulativeTime / g_statsTransactionCount / 1000 / 1000
   } else {
      report.Total = 0
      report.Average = 0
   }

   g_statsMutex.Unlock()

   // Build a json message from `report`
   message, err := json.Marshal (report)

   if nil != err {
      httpError (response, http.StatusInternalServerError, err.Error())
      return
   }

   // Configure the response with the json message
   response.Header().Set ("Content-Type", "application/json")
   response.Write (message)
}
