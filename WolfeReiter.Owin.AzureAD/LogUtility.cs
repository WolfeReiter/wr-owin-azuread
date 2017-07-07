using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace WolfeReiter.Owin.AzureAD
{
    internal static class LogUtility
    {
        public static void WriteEventLogEntry(string message, EventType eventType)
        {
            var entryType = eventType == EventType.Warning ? EventLogEntryType.Warning : EventLogEntryType.Error;

            //have to write a generic event source like "Application" because it requires admin rights to query or create event sources these days.
            EventLog.WriteEntry("Application", message, entryType);
            Debug.WriteLine(message);
            Trace.WriteLine(message);
        }

        public static string FormatException(Exception e, string description)
        {
            var module = Assembly.GetCallingAssembly().FullName;
            var machine = Environment.MachineName;
            var processIdentity = WindowsIdentity.GetCurrent();
            var thread = Thread.CurrentThread;
            var threadIdentity = Thread.CurrentPrincipal.Identity;
            var stackTrace = new StringBuilder(e.StackTrace);
            var message = new StringBuilder(string.Format("[{0}] {1}\r\n", e.GetType(), e.Message));

            //get recursive stack trace through all inner exceptions
            if (e is AggregateException)
            {
                var ax = e as AggregateException;
                foreach (var current in ax.InnerExceptions)
                {
                    var ex = current;
                    message.AppendLine(string.Format("[{0}] {1}", ex.GetType(), ex.Message));
                    stackTrace.AppendLine(ex.StackTrace);
                    
                    while (null != (ex = ex.InnerException))
                    {
                        message.AppendLine(string.Format("[{0}] {1}", ex.GetType(), ex.Message));
                        stackTrace.AppendLine(ex.StackTrace);
                    }
                }
            }
            else
            {
                var ex = e;
                while (null != (ex = ex.InnerException))
                {
                    message.AppendLine(string.Format("[{0}] {1}", ex.GetType(), ex.Message));
                    stackTrace.AppendLine(ex.StackTrace);
                }
            }

            var result = string.Format(
                    LoggingTemplate,
                    message.ToString().TrimEnd(), //0
                    description, //1
                    module, //2
                    machine, //3
                    threadIdentity.Name, //4
                    threadIdentity.ToString(), //5
                    threadIdentity.IsAuthenticated, //6
                    threadIdentity.AuthenticationType, //7
                    thread.ManagedThreadId, //8
                    processIdentity.Name, //9
                    processIdentity.ImpersonationLevel == System.Security.Principal.TokenImpersonationLevel.Impersonation, //10
                    stackTrace.ToString() //11
                    );

            return result;
        }

        static string FormatAggregateException(AggregateException e, string description)
        {
            var result = new StringBuilder(FormatException(e, description));
            int i = 1;
            foreach (var inner in e.InnerExceptions)
            {
                result.Append(FormatException(inner, string.Format("Inner Exception #{0}.", i)));
                i++;
            }
            return result.ToString();
        }

        const string LoggingTemplate = @"Event Message: {0}

Application Information
    Description: {1}
    Module: {2}

Security information:
    MachineName: {3}    
    User: {4}
    Identity: {5}
    Is authenticated: {6}
    Authentication Type: {7}

Thread information
    Thread ID: {8}
    Thread account name: {9}
    Is impersonating: {10}
    Stack trace: {11}";
    }

    enum EventType
    {
        Exception,
        Warning
    }
}
