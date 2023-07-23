/* How to build:
 *    g++ -std=c++11 fetch_certs.cpp -lssl -lcrypto -lpthread
 */

#include <boost/asio.hpp>
#include <iostream>

using namespace boost;

// subscription.packtpub.com/book/cloud-and-networking/9781783986545/1/ch01lvl1sec13/resolving-a-dns-name
std::string resolve_dns_address(const std::string& host_address)
{
  // Step 1. Assume that the client application has already
  // obtained the DNS name and protocol port number and 
  // represented them as strings.
  std::string host = host_address;
  std::string port_num = "443";

  // Step 2.
  asio::io_service ios;

  // Step 3. Creating a query.
  asio::ip::tcp::resolver::query resolver_query(host,
    port_num, asio::ip::tcp::resolver::query::numeric_service);

  // Step 4. Creating a resolver.
  asio::ip::tcp::resolver resolver(ios);

  // Used to store information about error that happens
  // during the resolution process.
  boost::system::error_code ec;

  // Step 5.
  asio::ip::tcp::resolver::iterator it =
    resolver.resolve(resolver_query, ec);

  return (ec.failed() ? "" /*ec.message()*/ : it->endpoint().address().to_string());
}

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>

// https://stackoverflow.com/a/41321247
int get_cert(const std::string& host, const std::string& ip)
{
  int s;
  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0)
  {
      std::cout << "Error creating socket. ";
      return -1;
  }
  struct sockaddr_in sa;
  memset (&sa, 0, sizeof(sa));
  sa.sin_family      = AF_INET;
  sa.sin_addr.s_addr = inet_addr(ip.c_str()); // address of google.ru
  sa.sin_port        = htons (443); 
  socklen_t socklen = sizeof(sa);
  if (connect(s, (struct sockaddr *)&sa, socklen))
  {
      std::cout << "Error connecting to server. ";
      return -1;
  }

  const SSL_METHOD *meth = TLS_client_method();
  SSL_CTX *ctx = SSL_CTX_new(meth);
  SSL* ssl = SSL_new(ctx);
  if (!ssl)
  {
      std::cout << "Error creating SSL. ";
      return -1;
  }
  int sock = SSL_get_fd(ssl);
  SSL_set_fd(ssl, s);
  int err = SSL_connect(ssl);
  if (err <= 0)
  {
      std::cout << "Error creating SSL connection. err=" << err << ". ";
      return -1;
  }

  X509 *cert = SSL_get_peer_certificate(ssl);
  FILE* fid = fopen(("certs/" + host + ".crt").c_str(), "wt");
  PEM_write_X509(fid, cert);
  fclose(fid);

  STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);
  int chain_length = sk_X509_num(chain);
  for (int i = 0; i < chain_length; i++)
  {
      X509 *cert = sk_X509_value(chain, i);
      FILE* fid = fopen(("certs_chain/" + host + "_" + std::to_string(i) + ".crt").c_str(), "wt");
      PEM_write_X509(fid, cert);
      fclose(fid);
  }

  SSL_CTX_free(ctx);
  return chain_length;
}

#include <fstream>
#include <iostream>

#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define NO_COLOR "\033[0m"

int main()
{
  SSL_library_init();
  SSLeay_add_ssl_algorithms();
  SSL_load_error_strings();

  std::ifstream fid{"address.txt"};
  std::ofstream resolved_fid{"resolved.txt"};
  std::string host{};
  int n_ok = 0;
  int n_all = 0;
  while (n_ok < 100)
  {
    ++n_all;
    fid >> host;
    std::cout << host << " : " << std::flush;
    std::string ip = resolve_dns_address(host);
    if (ip == "")
    {
      std::cout << "ERROR" << std::endl;
    }
    else if (ip == "0.0.0.0")
    {
      std::cout << "GAME" << std::endl;
    }
    else
    {
      std::cout << ip << " : " << std::flush;
      int cert_chain_size = get_cert(host, ip);
      if (cert_chain_size < 0)
      {
        std::cout << RED << "FAILED" << NO_COLOR << " [" << n_ok << "/" << n_all << "]" << std::endl;
      }
      else
      {
        ++n_ok;
        std::cout << GREEN << "DONE" << NO_COLOR << " [" << n_ok << "/" << n_all << "]" << std::endl;
        resolved_fid << host << " " << ip << " " << cert_chain_size << std::endl;
      }
    }
  }

  fid.close();
  resolved_fid.close();

  return 0;
}